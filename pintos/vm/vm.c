/* vm.c: Generic interface for virtual memory objects. */

#include "vm/vm.h"

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "vm/inspect.h"
static struct list frame_table;
struct list_elem *start;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
    vm_anon_init();
    vm_file_init();
#ifdef EFILESYS /* For project 4 */
    pagecache_init();
#endif
    register_inspect_intr();
    /* DO NOT MODIFY UPPER LINES. */
    /* TODO: Your code goes here. */
    list_init(&frame_table);
    start = list_begin(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
    int ty = VM_TYPE(page->operations->type);
    switch (ty)
    {
    case VM_UNINIT:
        return VM_TYPE(page->uninit.type);
    default:
        return ty;
    }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
                                    vm_initializer *init, void *aux)
{

    ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current()->spt;

    /* Check wheter the upage is already occupied or not. */
    if (spt_find_page(spt, upage) == NULL)
    {
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */
        struct page *p = (struct page *)malloc(sizeof(struct page));

        bool (*page_initializer)(struct page *, enum vm_type, void *kva);

        switch (VM_TYPE(type))
        {
        case VM_ANON:
            page_initializer = anon_initializer;
            break;
        case VM_FILE:
            page_initializer = file_backed_initializer;
            break;
        default:
            break;
        }

        uninit_new(p, upage, init, type, aux, page_initializer);

        p->writable = writable;

        /* TODO: Insert the page into the spt. */
        return spt_insert_page(spt, p);
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED)
{
    struct page *page = NULL;
    /* TODO: Fill this function. */
    page = (struct page *)malloc(sizeof(struct page));
    struct hash_elem *e;

    page->va = pg_round_down(va);
    e = hash_find(&(spt->hash_table), &(page->hash_elem));

    free(page);

    return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
                     struct page *page UNUSED)
{
    int succ = false;
    /* TODO: Fill this function. */

    if (hash_insert(&spt->hash_table, &page->hash_elem) == NULL)
        succ = true;

    return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
    hash_delete(&thread_current()->spt.hash_table, &page->hash_elem);
    vm_dealloc_page(page);
    return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim(void)
{
    struct frame *victim = NULL;
    /* TODO: The policy for eviction is up to you. */
    // project 3
    struct thread *curr = thread_current();
    struct list_elem *e = start;

    for (start = e; start != list_end(&frame_table); start = list_next(start))
    {
        victim = list_entry(start, struct frame, frame_elem);
        if (pml4_is_accessed(curr->pml4, victim->page->va))
            pml4_set_accessed(curr->pml4, victim->page->va, 0);
        else
        {
            return victim;
        }
    }
    for (start = list_begin(&frame_table); start != e; start = list_next(start))
    {
        victim = list_entry(start, struct frame, frame_elem);
        if (pml4_is_accessed(curr->pml4, victim->page->va))
            pml4_set_accessed(curr->pml4, victim->page->va, 0);
        else
        {
            return victim;
        }
    }
    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
    struct frame *victim UNUSED = vm_get_victim();
    /* TODO: swap out the victim and return the evicted frame. */
    if (victim->page != NULL)
    {
        swap_out(victim->page);
    }

    return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame(void)
{
    /* TODO: Fill this function. */
    struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
    ASSERT(frame != NULL);

    frame->kva = palloc_get_page(PAL_USER | PAL_ZERO); // 유저 풀(실제 메모리)에서 페이지를 할당 받는다.

    if (frame->kva == NULL)
        frame = vm_evict_frame(); // Swap Out 수행
    else
        list_push_back(&frame_table, &frame->frame_elem); // frame table에 추가

    frame->page = NULL;
    ASSERT(frame->page == NULL);

    return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
    bool success = false;
    if (vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true))
    {
        success = vm_claim_page(addr);

        if (success)
        {
            /* stack bottom size 갱신 */
            thread_current()->stack_bottom -= PGSIZE;
        }
    }
}

/* Handle the fault on write_protected page */
bool vm_handle_wp(struct page *page UNUSED)
{
    if (!page->accessible)
        return false;

    void *kva = page->frame->kva;

    page->frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);

    if (page->frame->kva == NULL)
        page->frame = vm_evict_frame(); // Swap Out 수행

    memcpy(page->frame->kva, kva, PGSIZE);

    if (!pml4_set_page(thread_current()->pml4, page->va, page->frame->kva, page->accessible))
        return false;

    return true;
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED, bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = spt_find_page(&thread_current()->spt, addr);

    /* TODO: Validate the fault */
    if (addr == NULL || is_kernel_vaddr(addr))
        return false;

    /** Project 3: Copy On Write (Extra) - 접근한 메모리의 page가 존재하고 write 요청인데 write protected인 경우라 발생한 fault일 경우*/
    if (!not_present && write)
        return vm_handle_wp(page);

    /** Project 3: Copy On Write (Extra) - 이전에 만들었던 페이지인데 swap out되어서 현재 spt에서 삭제하였을 때 stack_growth 대신 claim_page를 하기 위해 조건 분기 */
    if (!page)
    {
        /** Project 3: Stack Growth - stack growth로 처리할 수 있는 경우 */
        /* stack pointer 아래 8바이트는 페이지 폴트 발생 & addr 위치를 USER_STACK에서 1MB로 제한 */
        void *stack_pointer = user ? f->rsp : thread_current()->stack_pointer;
        if (stack_pointer - 8 <= addr && addr >= USER_STACK - MAX_STACK_POINT && addr <= USER_STACK)
        {
            vm_stack_growth(thread_current()->stack_bottom - PGSIZE);
            return true;
        }
        return false;
    }

    return vm_do_claim_page(page); // demand page 수행
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
    destroy(page);
    free(page);
}

/** Project 3: Copy On Write (Extra) - VA에 할당된 페이지를 복제. */
static bool vm_copy_claim_page(struct supplemental_page_table *dst, void *va, void *kva, bool writable)
{
    struct page *page = spt_find_page(dst, va);

    if (page == NULL)
        return false;

    struct frame *frame = (struct frame *)malloc(sizeof(struct frame));

    if (!frame)
        return false;

    /* Set links */
    page->accessible = writable; // 접근 권한 설정
    frame->page = page;
    page->frame = frame;
    frame->kva = kva;

    if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, false))
    {
        free(frame);
        return false;
    }

    list_push_back(&frame_table, &frame->frame_elem); // frame table에 추가

    return swap_in(page, frame->kva);
}
/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED)
{
    struct page *page = NULL;
    /* TODO: Fill this function */
    page = spt_find_page(&thread_current()->spt, va);

    if (page == NULL)
        return false;

    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page(struct page *page)
{
    struct frame *frame = vm_get_frame();

    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    struct thread *current = thread_current();
    if (!pml4_set_page(current->pml4, page->va, frame->kva, page->writable))
        return false;

    return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
    hash_init(&spt->hash_table, hash_func, less_func, NULL);
}

/** Project 3: Anonymous Page - Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED, struct supplemental_page_table *src UNUSED)
{
    struct hash_iterator iter;
    struct page *dst_page;
    struct aux *aux;

    hash_first(&iter, &src->hash_table);

    while (hash_next(&iter))
    {
        struct page *src_page = hash_entry(hash_cur(&iter), struct page, hash_elem);
        enum vm_type type = src_page->operations->type;
        void *upage = src_page->va;
        bool writable = src_page->writable;
        struct uninit_page *uninit = &src_page->uninit;

        switch (type)
        {
        case VM_UNINIT: // src 타입이 initialize 되지 않았을 경우
            aux = uninit->aux;
            struct lazy_load_arg *lazy_load_arg = malloc(sizeof(struct lazy_load_arg));
            if (lazy_load_arg == NULL)
            {
                // malloc fail - kernel pool all used
            }
            memcpy(lazy_load_arg, (struct lazy_load_arg *)aux, sizeof(struct lazy_load_arg));

            lazy_load_arg->file = file_reopen(((struct lazy_load_arg *)aux)->file); // get new struct file (calloc)
            vm_alloc_page_with_initializer(uninit->type, src_page->va, src_page->writable, uninit->init, lazy_load_arg);
            break;

        case VM_FILE: // src 타입이 FILE인 경우
            if (!vm_alloc_page_with_initializer(type, upage, writable, NULL, &src_page->file))
                goto err;

            dst_page = spt_find_page(dst, upage); // 대응하는 물리 메모리 데이터 복제
            if (!file_backed_initializer(dst_page, type, NULL))
                goto err;

            dst_page->frame = src_page->frame;
            if (!pml4_set_page(thread_current()->pml4, dst_page->va, src_page->frame->kva, src_page->writable))
                goto err;
            break;

        case VM_ANON:                                  // src 타입이 anon인 경우
            if (!vm_alloc_page(type, upage, writable)) // UNINIT 페이지 생성 및 초기화
                goto err;
            if (!vm_copy_claim_page(dst, upage, src_page->frame->kva, writable)) // 물리 메모리와 매핑하고 initialize
                goto err;

            break;

        default:
            goto err;
        }
    }

    return true;

err:
    return false;
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
    hash_clear(&spt->hash_table, hash_destructor);
}
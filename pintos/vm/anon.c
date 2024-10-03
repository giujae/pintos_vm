/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include <bitmap.h>

#define SECTORS_IN_PAGE 8// 4kB / 512 (DISK_SECTOR_SIZE)
struct bitmap *swap_table;
size_t slot_max;

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
    swap_disk = disk_get(1, 1);
    slot_max = disk_size(swap_disk) / SECTORS_IN_PAGE;
    swap_table = bitmap_create(slot_max);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
    /* 데이터를 모두 0으로 초기화 */
    struct uninit_page *uninit = &page->uninit;
    memset(uninit, 0, sizeof(struct uninit_page));

    page->operations = &anon_ops;

    struct anon_page *anon_page = &page->anon;
    /** Project 3: Swap In/Out - ERROR로 초기화  */
    anon_page->slot = BITMAP_ERROR;

    return true;

}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
    struct anon_page *anon_page = &page->anon;
    size_t slot = anon_page->slot;
    size_t sector = slot * SECTORS_IN_PAGE;

    if (slot == BITMAP_ERROR || !bitmap_test(swap_table, slot))
        return false;

    bitmap_set(swap_table, slot, false);

    for (size_t i = 0; i < SECTORS_IN_PAGE; i++)
        disk_read(swap_disk, sector + i, kva + DISK_SECTOR_SIZE * i);

    sector = BITMAP_ERROR;

    return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
    struct anon_page *anon_page = &page->anon;

    size_t free_idx = bitmap_scan_and_flip(swap_table, 0, 1, false);

    if (free_idx == BITMAP_ERROR)
        return false;

    size_t sector = free_idx * SECTORS_IN_PAGE;

    for (size_t i = 0; i < SECTORS_IN_PAGE; i++)
        disk_write(swap_disk, sector + i, page->va + DISK_SECTOR_SIZE * i);

    anon_page->slot = free_idx;

    page->frame->page = NULL;
    page->frame = NULL;
    pml4_clear_page(thread_current()->pml4, page->va);

    return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
    struct anon_page *anon_page = &page->anon;

    /** Project 3: Swap In/Out - 점거중인 bitmap 삭제 */
    if (anon_page->slot != BITMAP_ERROR)
        bitmap_reset(swap_table, anon_page->slot);

    /** Project 3: Anonymous Page - 점거중인 frame 삭제 */
    if (page->frame) {
        list_remove(&page->frame->frame_elem);
        page->frame->page = NULL;
        free(page->frame);
        page->frame = NULL;
    }

    /** Project 3: Copy on Write (Extra) - destroy 시 pml4 clear하여 참조하던 kva들을 모두 해제한다.
     * 그렇지 않으면 자식에서 `exit`시 참조한 부모의 kva가 파괴되어 자식이 부모에서 해당 kva에 접근할 수 없기 때문이다. */
    pml4_clear_page(thread_current()->pml4, page->va);
}

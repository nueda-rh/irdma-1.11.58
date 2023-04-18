/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2015 - 2022 Intel Corporation */
#ifndef IRDMA_VERBS_H
#define IRDMA_VERBS_H

#define IRDMA_MAX_SAVED_PHY_PGADDR	4
#define IRDMA_FLUSH_DELAY_MS		20

#define IRDMA_PKEY_TBL_SZ		1
#define IRDMA_DEFAULT_PKEY		0xFFFF

#define iwdev_to_idev(iwdev)	(&(iwdev)->rf->sc_dev)

struct irdma_ucontext {
	struct ib_ucontext ibucontext;
	struct irdma_device *iwdev;
#ifdef RDMA_MMAP_DB_SUPPORT
	struct rdma_user_mmap_entry *db_mmap_entry;
#else
	struct irdma_user_mmap_entry *db_mmap_entry;
	DECLARE_HASHTABLE(mmap_hash_tbl, 6);
	spinlock_t mmap_tbl_lock; /* protect mmap hash table entries */
#endif
	struct list_head cq_reg_mem_list;
	spinlock_t cq_reg_mem_list_lock; /* protect CQ memory list */
	struct list_head qp_reg_mem_list;
	spinlock_t qp_reg_mem_list_lock; /* protect QP memory list */
#ifdef CONFIG_DEBUG_FS
	struct list_head uctx_list;
#endif
	/* FIXME: Move to kcompat ideally. Used < 4.20.0 for old diassasscoaite flow */
	struct list_head vma_list;
	struct mutex vma_list_mutex; /* protect the vma_list */
	int abi_ver;
	bool legacy_mode:1;
	bool use_raw_attrs:1;
};

struct irdma_pd {
	struct ib_pd ibpd;
	struct irdma_sc_pd sc_pd;
};

struct irdma_av {
	u8 macaddr[16];
	struct rdma_ah_attr attrs;
	union {
		struct sockaddr saddr;
		struct sockaddr_in saddr_in;
		struct sockaddr_in6 saddr_in6;
	} sgid_addr, dgid_addr;
	u8 net_type;
};

struct irdma_ah {
	struct ib_ah ibah;
	struct irdma_sc_ah sc_ah;
	struct irdma_pd *pd;
	struct irdma_av av;
	u8 sgid_index;
	union ib_gid dgid;
	struct hlist_node list;
	refcount_t refcnt;
	struct irdma_ah *parent_ah;	/* AH from cached list */
};

struct irdma_hmc_pble {
	union {
		u32 idx;
		dma_addr_t addr;
	};
};

struct irdma_cq_mr {
	struct irdma_hmc_pble cq_pbl;
	dma_addr_t shadow;
	bool split;
};

struct irdma_qp_mr {
	struct irdma_hmc_pble sq_pbl;
	struct irdma_hmc_pble rq_pbl;
	dma_addr_t shadow;
	struct page *sq_page;
};

struct irdma_cq_buf {
	struct irdma_dma_mem kmem_buf;
	struct irdma_cq_uk cq_uk;
	struct irdma_hw *hw;
	struct list_head list;
	struct work_struct work;
};

struct irdma_pbl {
	struct list_head list;
	union {
		struct irdma_qp_mr qp_mr;
		struct irdma_cq_mr cq_mr;
	};

	bool pbl_allocated:1;
	bool on_list:1;
	u64 user_base;
	struct irdma_pble_alloc pble_alloc;
	struct irdma_mr *iwmr;
};

struct irdma_mr {
	union {
		struct ib_mr ibmr;
		struct ib_mw ibmw;
	};
	struct ib_umem *region;
	int access;
	u8 is_hwreg;
	u16 type;
	u32 page_cnt;
	u64 page_size;
	u64 page_msk;
	u32 npages;
	u32 stag;
	u64 len;
	u64 pgaddrmem[IRDMA_MAX_SAVED_PHY_PGADDR];
#ifdef CONFIG_DEBUG_FS
	u64 level0_pa;
#endif
	struct irdma_pbl iwpbl;
};

struct irdma_cq {
	struct ib_cq ibcq;
	struct irdma_sc_cq sc_cq;
	u16 cq_head;
	u16 cq_size;
	u16 cq_num;
	bool user_mode;
	atomic_t armed;
	enum irdma_cmpl_notify last_notify;
	u32 polled_cmpls;
	u32 cq_mem_size;
	struct irdma_dma_mem kmem;
	struct irdma_dma_mem kmem_shadow;
	struct completion free_cq;
	refcount_t refcnt;
	spinlock_t lock; /* for poll cq */
	struct irdma_pbl *iwpbl;
	struct irdma_pbl *iwpbl_shadow;
	struct list_head resize_list;
	struct irdma_cq_poll_info cur_cqe;
	struct list_head cmpl_generated;
};

struct irdma_cmpl_gen {
	struct list_head list;
	struct irdma_cq_poll_info cpi;
};

struct disconn_work {
	struct work_struct work;
	struct irdma_qp *iwqp;
};

struct if_notify_work {
	struct work_struct work;
	struct irdma_device *iwdev;
	u32 ipaddr[4];
	u16 vlan_id;
	bool ipv4:1;
	bool ifup:1;
};

struct iw_cm_id;

struct irdma_qp_kmode {
	struct irdma_dma_mem dma_mem;
	struct irdma_sq_uk_wr_trk_info *sq_wrid_mem;
	u64 *rq_wrid_mem;
};

struct irdma_qp {
	struct ib_qp ibqp;
	struct irdma_sc_qp sc_qp;
	struct irdma_device *iwdev;
	struct irdma_cq *iwscq;
	struct irdma_cq *iwrcq;
	struct irdma_pd *iwpd;
#ifdef RDMA_MMAP_DB_SUPPORT
	struct rdma_user_mmap_entry *push_wqe_mmap_entry;
	struct rdma_user_mmap_entry *push_db_mmap_entry;
#else
	struct irdma_user_mmap_entry *push_wqe_mmap_entry;
	struct irdma_user_mmap_entry *push_db_mmap_entry;
#endif
	struct irdma_qp_host_ctx_info ctx_info;
	union {
		struct irdma_iwarp_offload_info iwarp_info;
		struct irdma_roce_offload_info roce_info;
	};

	union {
		struct irdma_tcp_offload_info tcp_info;
		struct irdma_udp_offload_info udp_info;
	};

	struct irdma_ah roce_ah;
	struct list_head teardown_entry;
	refcount_t refcnt;
	struct iw_cm_id *cm_id;
	struct irdma_cm_node *cm_node;
	struct delayed_work dwork_flush;
	struct ib_mr *lsmm_mr;
	atomic_t hw_mod_qp_pend;
	enum ib_qp_state ibqp_state;
	u32 qp_mem_size;
	u32 last_aeq;
	int max_send_wr;
	int max_recv_wr;
	atomic_t close_timer_started;
	spinlock_t lock; /* serialize posting WRs to SQ/RQ */
	struct irdma_qp_context *iwqp_context;
	void *pbl_vbase;
	dma_addr_t pbl_pbase;
	struct page *page;
	u8 iwarp_state;
	u16 term_sq_flush_code;
	u16 term_rq_flush_code;
	u8 hw_iwarp_state;
	u8 hw_tcp_state;
	struct irdma_qp_kmode kqp;
	struct irdma_dma_mem host_ctx;
	struct timer_list terminate_timer;
	struct irdma_pbl *iwpbl;
	struct irdma_sge *sg_list;
	struct irdma_dma_mem q2_ctx_mem;
	struct irdma_dma_mem ietf_mem;
	struct completion free_qp;
	wait_queue_head_t waitq;
	wait_queue_head_t mod_qp_waitq;
	u8 rts_ae_rcvd;
	u8 active_conn : 1;
	u8 user_mode : 1;
	u8 hte_added : 1;
	u8 flush_issued : 1;
	u8 sig_all : 1;
	u8 pau_mode : 1;
};

enum irdma_mmap_flag {
	IRDMA_MMAP_IO_NC,
	IRDMA_MMAP_IO_WC,
};

struct irdma_user_mmap_entry {
#ifdef RDMA_MMAP_DB_SUPPORT
	struct rdma_user_mmap_entry rdma_entry;
#else
	struct irdma_ucontext *ucontext;
	struct hlist_node hlist;
	u64 pgoff_key; /* Used to compute offset (in bytes) returned to user libc's mmap */
#endif
	u64 bar_offset;
	u8 mmap_flag;
};

static inline u16 irdma_fw_major_ver(struct irdma_sc_dev *dev)
{
	return (u16)FIELD_GET(IRDMA_FW_VER_MAJOR, dev->feature_info[IRDMA_FEATURE_FW_INFO]);
}

static inline u16 irdma_fw_minor_ver(struct irdma_sc_dev *dev)
{
	return (u16)FIELD_GET(IRDMA_FW_VER_MINOR, dev->feature_info[IRDMA_FEATURE_FW_INFO]);
}

/**
 * irdma_mcast_mac_v4 - Get the multicast MAC for an IP address
 * @ip_addr: IPv4 address
 * @mac: pointer to result MAC address
 *
 */
static inline void irdma_mcast_mac_v4(u32 *ip_addr, u8 *mac)
{
	u8 *ip = (u8 *)ip_addr;
	unsigned char mac4[ETH_ALEN] = {0x01, 0x00, 0x5E, ip[2] & 0x7F, ip[1],
					ip[0]};

	ether_addr_copy(mac, mac4);
}

/**
 * irdma_mcast_mac_v6 - Get the multicast MAC for an IP address
 * @ip_addr: IPv6 address
 * @mac: pointer to result MAC address
 *
 */
static inline void irdma_mcast_mac_v6(u32 *ip_addr, u8 *mac)
{
	u8 *ip = (u8 *)ip_addr;
	unsigned char mac6[ETH_ALEN] = {0x33, 0x33, ip[3], ip[2], ip[1], ip[0]};

	ether_addr_copy(mac, mac6);
}

#ifdef ALLOC_HW_STATS_STRUCT_V2
extern const struct rdma_stat_desc irdma_hw_stat_descs[];

#endif /* ALLOC_HW_STATS_STRUCT_V2 */
#ifdef RDMA_MMAP_DB_SUPPORT
struct rdma_user_mmap_entry*
irdma_user_mmap_entry_insert(struct irdma_ucontext *ucontext, u64 bar_offset,
			     enum irdma_mmap_flag mmap_flag, u64 *mmap_offset);
#else
struct irdma_user_mmap_entry *
irdma_user_mmap_entry_add_hash(struct irdma_ucontext *ucontext, u64 bar_offset,
			       enum irdma_mmap_flag mmap_flag, u64 *mmap_offset);
void irdma_user_mmap_entry_del_hash(struct irdma_user_mmap_entry *entry);
#endif /* RDMA_MMAP_DB_SUPPORT */
int irdma_ib_register_device(struct irdma_device *iwdev);
void irdma_ib_unregister_device(struct irdma_device *iwdev);
void irdma_ib_qp_event(struct irdma_qp *iwqp, enum irdma_qp_event_type event);
void irdma_generate_flush_completions(struct irdma_qp *iwqp);
void irdma_remove_cmpls_list(struct irdma_cq *iwcq);
int irdma_generated_cmpls(struct irdma_cq *iwcq, struct irdma_cq_poll_info *cq_poll_info);
void irdma_sched_qp_flush_work(struct irdma_qp *iwqp);
void irdma_flush_worker(struct work_struct *work);
#endif /* IRDMA_VERBS_H */

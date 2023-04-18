/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2015 - 2021 Intel Corporation */
#ifndef IRDMA_VF_H
#define IRDMA_VF_H

struct irdma_sc_cqp;

struct irdma_manage_vf_pble_info {
	u32 sd_index;
	u16 first_pd_index;
	u16 pd_entry_cnt;
	u8 inv_pd_ent;
	u64 pd_pl_pba;
};

int irdma_manage_vf_pble_bp(struct irdma_sc_cqp *cqp,
			    struct irdma_manage_vf_pble_info *info, u64 scratch,
			    bool post_sq);
#endif

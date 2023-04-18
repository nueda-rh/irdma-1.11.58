/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2015 - 2022 Intel Corporation */
#ifndef IRDMA_VIRTCHNL_H
#define IRDMA_VIRTCHNL_H

#include "hmc.h"
#include "irdma.h"

#pragma pack(push, 1)

struct irdma_virtchnl_op_buf {
	u16 op_code;
	u16 op_ver;
	u16 buf_len;
	u16 rsvd;
	u64 op_ctx;
	/* Member alignment MUST be maintained above this location */
	u8 buf[];
};

struct irdma_virtchnl_resp_buf {
	u64 op_ctx;
	u16 buf_len;
	s16 op_ret_code;
	/* Member alignment MUST be maintained above this location */
	u16 rsvd[2];
	u8 buf[];
};

enum irdma_virtchnl_ops {
	IRDMA_VCHNL_OP_GET_VER = 0,
	IRDMA_VCHNL_OP_GET_HMC_FCN = 1,
	IRDMA_VCHNL_OP_PUT_HMC_FCN = 2,
	IRDMA_VCHNL_OP_ADD_HMC_OBJ_RANGE = 3,
	IRDMA_VCHNL_OP_DEL_HMC_OBJ_RANGE = 4,
	IRDMA_VCHNL_OP_GET_STATS = 5,
	IRDMA_VCHNL_OP_MANAGE_STATS_INST = 6,
	IRDMA_VCHNL_OP_MCG = 7,
	IRDMA_VCHNL_OP_UP_MAP = 8,
	IRDMA_VCHNL_OP_MANAGE_WS_NODE = 9,
	IRDMA_VCHNL_OP_VLAN_PARSING = 12,
	IRDMA_VCHNL_OP_GET_RDMA_CAPS = 13,
};

/* IRDMA_VCHNL_CHNL_VER_V0 is for legacy hw, no longer supported. */
#define IRDMA_VCHNL_CHNL_VER_V0 0
#define IRDMA_VCHNL_CHNL_VER_V1 1
#define IRDMA_VCHNL_CHNL_VER_V2 2
#define IRDMA_VCHNL_CHNL_VER_MIN IRDMA_VCHNL_CHNL_VER_V1
#define IRDMA_VCHNL_CHNL_VER_MAX IRDMA_VCHNL_CHNL_VER_V2

#define IRDMA_VCHNL_OP_GET_VER_V0 0
#define IRDMA_VCHNL_OP_GET_VER_V1 1
#define IRDMA_VCHNL_OP_GET_VER_V2 2

#define IRDMA_VCHNL_OP_GET_HMC_FCN_V0 0
#define IRDMA_VCHNL_OP_PUT_HMC_FCN_V0 0
#define IRDMA_VCHNL_OP_ADD_HMC_OBJ_RANGE_V0 0
#define IRDMA_VCHNL_OP_DEL_HMC_OBJ_RANGE_V0 0
#define IRDMA_VCHNL_OP_GET_STATS_V0 0
#define IRDMA_VCHNL_OP_MANAGE_WS_NODE_V0 0
#define IRDMA_VCHNL_OP_VLAN_PARSING_V0 0
#define IRDMA_VCHNL_OP_GET_RDMA_CAPS_V0 0
#define IRDMA_VCHNL_INVALID_VF_IDX 0xFFFF

struct irdma_virtchnl_hmc_obj_range {
	u16 obj_type;
	u16 rsvd;
	u32 start_index;
	u32 obj_count;
};

struct irdma_virtchnl_manage_ws_node {
	u8 add;
	u8 user_pri;
};

struct irdma_virtchnl_rdma_caps {
	u8 hw_rev;
};

struct irdma_virtchnl_init_info {
	struct workqueue_struct *vchnl_wq;
	struct irdma_vchnl_if *vchnl_if;
	enum irdma_vers hw_rev;
	bool privileged;
};

int irdma_vchnl_recv_pf(struct irdma_sc_dev *dev, u16 vf_id, u8 *msg, u16 len);
int irdma_vchnl_recv_vf(struct irdma_sc_dev *dev, u16 vf_id, u8 *msg, u16 len);
struct irdma_vfdev *irdma_find_vf_dev(struct irdma_sc_dev *dev, u16 vf_id);
void irdma_put_vfdev(struct irdma_sc_dev *dev, struct irdma_vfdev *vf_dev);
void irdma_remove_vf_dev(struct irdma_sc_dev *dev, struct irdma_vfdev *vf_dev);
struct irdma_virtchnl_req {
	struct irdma_virtchnl_op_buf *vchnl_msg;
	void *parm;
	u32 vf_id;
	u16 parm_len;
	u16 resp_len;
};

#pragma pack(pop)

int irdma_sc_vchnl_init(struct irdma_sc_dev *dev,
			struct irdma_virtchnl_init_info *info);
int irdma_vchnl_vf_get_ver(struct irdma_sc_dev *dev, u16 ver_req, u32 *ver_res);
int irdma_vchnl_vf_get_hmc_fcn(struct irdma_sc_dev *dev);
int irdma_vchnl_vf_put_hmc_fcn(struct irdma_sc_dev *dev);
int irdma_vchnl_vf_add_hmc_objs(struct irdma_sc_dev *dev,
				enum irdma_hmc_rsrc_type rsrc_type,
				u32 start_index, u32 rsrc_count);
int irdma_vchnl_vf_del_hmc_obj(struct irdma_sc_dev *dev,
			       enum irdma_hmc_rsrc_type rsrc_type,
			       u32 start_index, u32 rsrc_count);
int irdma_vchnl_vf_manage_ws_node(struct irdma_sc_dev *dev, bool add,
				  u8 user_pri, u16 *qs_handle);
int irdma_vchnl_vf_get_vlan_parsing_cfg(struct irdma_sc_dev *dev,
					u8 *vlan_parse_en);
int irdma_vchnl_vf_get_capabilities(struct irdma_sc_dev *dev);
void irdma_pf_put_vf_hmc_fcn(struct irdma_sc_dev *dev, struct irdma_vfdev *vf_dev);
#endif

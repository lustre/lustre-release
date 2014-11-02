/**
 * \file lustre_dlm_flags_wshark.c
 *
 * wireshark definitions.  This file contains the ldlm lock flag bits
 * that can be transmitted over the wire.  There are many other bits,
 * but they are not transmitted and not handled here.
 */
#ifdef WSHARK_HEAD

static int hf_lustre_ldlm_fl_lock_changed        = -1;
static int hf_lustre_ldlm_fl_block_granted       = -1;
static int hf_lustre_ldlm_fl_block_conv          = -1;
static int hf_lustre_ldlm_fl_block_wait          = -1;
static int hf_lustre_ldlm_fl_ast_sent            = -1;
static int hf_lustre_ldlm_fl_replay              = -1;
static int hf_lustre_ldlm_fl_intent_only         = -1;
static int hf_lustre_ldlm_fl_has_intent          = -1;
static int hf_lustre_ldlm_fl_flock_deadlock      = -1;
static int hf_lustre_ldlm_fl_discard_data        = -1;
static int hf_lustre_ldlm_fl_no_timeout          = -1;
static int hf_lustre_ldlm_fl_block_nowait        = -1;
static int hf_lustre_ldlm_fl_test_lock           = -1;
static int hf_lustre_ldlm_fl_cancel_on_block     = -1;
static int hf_lustre_ldlm_fl_cos_incompat        = -1;
static int hf_lustre_ldlm_fl_deny_on_contention  = -1;
static int hf_lustre_ldlm_fl_ast_discard_data    = -1;

const value_string lustre_ldlm_flags_vals[] = {
  {LDLM_FL_LOCK_CHANGED,        "LDLM_FL_LOCK_CHANGED"},
  {LDLM_FL_BLOCK_GRANTED,       "LDLM_FL_BLOCK_GRANTED"},
  {LDLM_FL_BLOCK_CONV,          "LDLM_FL_BLOCK_CONV"},
  {LDLM_FL_BLOCK_WAIT,          "LDLM_FL_BLOCK_WAIT"},
  {LDLM_FL_AST_SENT,            "LDLM_FL_AST_SENT"},
  {LDLM_FL_REPLAY,              "LDLM_FL_REPLAY"},
  {LDLM_FL_INTENT_ONLY,         "LDLM_FL_INTENT_ONLY"},
  {LDLM_FL_HAS_INTENT,          "LDLM_FL_HAS_INTENT"},
  {LDLM_FL_FLOCK_DEADLOCK,      "LDLM_FL_FLOCK_DEADLOCK"},
  {LDLM_FL_DISCARD_DATA,        "LDLM_FL_DISCARD_DATA"},
  {LDLM_FL_NO_TIMEOUT,          "LDLM_FL_NO_TIMEOUT"},
  {LDLM_FL_BLOCK_NOWAIT,        "LDLM_FL_BLOCK_NOWAIT"},
  {LDLM_FL_TEST_LOCK,           "LDLM_FL_TEST_LOCK"},
  {LDLM_FL_CANCEL_ON_BLOCK,     "LDLM_FL_CANCEL_ON_BLOCK"},
  {LDLM_FL_COS_INCOMPAT,        "LDLM_FL_COS_INCOMPAT"},
  {LDLM_FL_DENY_ON_CONTENTION,  "LDLM_FL_DENY_ON_CONTENTION"},
  {LDLM_FL_AST_DISCARD_DATA,    "LDLM_FL_AST_DISCARD_DATA"},
  { 0, NULL }
};

/* IDL: struct ldlm_reply { */
/* IDL: 	uint32 lock_flags; */
/* IDL: 	uint32 lock_padding; */
/* IDL: 	struct ldlm_lock_desc { */
/* IDL: } lock_desc; */
/* IDL: 	struct lustre_handle { */
/* IDL: } lock_handle; */
/* IDL: 	uint64 lock_policy_res1; */
/* IDL: 	uint64 lock_policy_res2; */
/* IDL: } */

static int
lustre_dissect_element_ldlm_lock_flags(
	tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_,
	proto_tree *parent_tree _U_, int hf_index _U_)
{
  proto_item *item = NULL;
  proto_tree *tree = NULL;

  if (parent_tree) {
    item = proto_tree_add_item(parent_tree,hf_index, tvb, offset, 4, TRUE);
    tree = proto_item_add_subtree(item, ett_lustre_ldlm_lock_flags);
  }
  dissect_uint32(tvb, offset, pinfo, tree, hf_lustre_ldlm_fl_lock_changed);
  dissect_uint32(tvb, offset, pinfo, tree, hf_lustre_ldlm_fl_block_granted);
  dissect_uint32(tvb, offset, pinfo, tree, hf_lustre_ldlm_fl_block_conv);
  dissect_uint32(tvb, offset, pinfo, tree, hf_lustre_ldlm_fl_block_wait);
  dissect_uint32(tvb, offset, pinfo, tree, hf_lustre_ldlm_fl_ast_sent);
  dissect_uint32(tvb, offset, pinfo, tree, hf_lustre_ldlm_fl_replay);
  dissect_uint32(tvb, offset, pinfo, tree, hf_lustre_ldlm_fl_intent_only);
  dissect_uint32(tvb, offset, pinfo, tree, hf_lustre_ldlm_fl_has_intent);
  dissect_uint32(tvb, offset, pinfo, tree, hf_lustre_ldlm_fl_flock_deadlock);
  dissect_uint32(tvb, offset, pinfo, tree, hf_lustre_ldlm_fl_discard_data);
  dissect_uint32(tvb, offset, pinfo, tree, hf_lustre_ldlm_fl_no_timeout);
  dissect_uint32(tvb, offset, pinfo, tree, hf_lustre_ldlm_fl_block_nowait);
  dissect_uint32(tvb, offset, pinfo, tree, hf_lustre_ldlm_fl_test_lock);
  dissect_uint32(tvb, offset, pinfo, tree, hf_lustre_ldlm_fl_cancel_on_block);
  dissect_uint32(tvb, offset, pinfo, tree, hf_lustre_ldlm_fl_cos_incompat);
  dissect_uint32(tvb, offset, pinfo, tree, hf_lustre_ldlm_fl_deny_on_contention);
  return
    dissect_uint32(tvb, offset, pinfo, tree, hf_lustre_ldlm_fl_ast_discard_data);
}
#endif /* WSHARK_HEAD */

#ifdef WSHARK_INIT_DATA
  {
    /* p_id    */ &hf_lustre_ldlm_fl_lock_changed,
    /* hfinfo  */ {
      /* name    */ "LDLM_FL_LOCK_CHANGED",
      /* abbrev  */ "lustre.ldlm_fl_lock_changed",
      /* type    */ FT_BOOLEAN,
      /* display */ 32,
      /* strings */ TFS(&lnet_flags_set_truth),
      /* bitmask */ LDLM_FL_LOCK_CHANGED,
      /* blurb   */ "extent, mode, or resource changed",
      /* id      */ HFILL
    }
  },
  {
    /* p_id    */ &hf_lustre_ldlm_fl_block_granted,
    /* hfinfo  */ {
      /* name    */ "LDLM_FL_BLOCK_GRANTED",
      /* abbrev  */ "lustre.ldlm_fl_block_granted",
      /* type    */ FT_BOOLEAN,
      /* display */ 32,
      /* strings */ TFS(&lnet_flags_set_truth),
      /* bitmask */ LDLM_FL_BLOCK_GRANTED,
      /* blurb   */ "Server placed lock on granted list, or a recovering client wants\n"
       "the lock added to the granted list, no questions asked.",
      /* id      */ HFILL
    }
  },
  {
    /* p_id    */ &hf_lustre_ldlm_fl_block_conv,
    /* hfinfo  */ {
      /* name    */ "LDLM_FL_BLOCK_CONV",
      /* abbrev  */ "lustre.ldlm_fl_block_conv",
      /* type    */ FT_BOOLEAN,
      /* display */ 32,
      /* strings */ TFS(&lnet_flags_set_truth),
      /* bitmask */ LDLM_FL_BLOCK_CONV,
      /* blurb   */ "Server placed lock on conv list, or a recovering client wants the lock\n"
       "added to the conv list, no questions asked.",
      /* id      */ HFILL
    }
  },
  {
    /* p_id    */ &hf_lustre_ldlm_fl_block_wait,
    /* hfinfo  */ {
      /* name    */ "LDLM_FL_BLOCK_WAIT",
      /* abbrev  */ "lustre.ldlm_fl_block_wait",
      /* type    */ FT_BOOLEAN,
      /* display */ 32,
      /* strings */ TFS(&lnet_flags_set_truth),
      /* bitmask */ LDLM_FL_BLOCK_WAIT,
      /* blurb   */ "Server placed lock on wait list, or a recovering client wants\n"
       "the lock added to the wait list, no questions asked.",
      /* id      */ HFILL
    }
  },
  {
    /* p_id    */ &hf_lustre_ldlm_fl_ast_sent,
    /* hfinfo  */ {
      /* name    */ "LDLM_FL_AST_SENT",
      /* abbrev  */ "lustre.ldlm_fl_ast_sent",
      /* type    */ FT_BOOLEAN,
      /* display */ 32,
      /* strings */ TFS(&lnet_flags_set_truth),
      /* bitmask */ LDLM_FL_AST_SENT,
      /* blurb   */ "blocking or cancel packet was queued for sending.",
      /* id      */ HFILL
    }
  },
  {
    /* p_id    */ &hf_lustre_ldlm_fl_replay,
    /* hfinfo  */ {
      /* name    */ "LDLM_FL_REPLAY",
      /* abbrev  */ "lustre.ldlm_fl_replay",
      /* type    */ FT_BOOLEAN,
      /* display */ 32,
      /* strings */ TFS(&lnet_flags_set_truth),
      /* bitmask */ LDLM_FL_REPLAY,
      /* blurb   */ "Lock is being replayed.  This could probably be implied by the fact that\n"
       "one of BLOCK_{GRANTED,CONV,WAIT} is set, but that is pretty dangerous.",
      /* id      */ HFILL
    }
  },
  {
    /* p_id    */ &hf_lustre_ldlm_fl_intent_only,
    /* hfinfo  */ {
      /* name    */ "LDLM_FL_INTENT_ONLY",
      /* abbrev  */ "lustre.ldlm_fl_intent_only",
      /* type    */ FT_BOOLEAN,
      /* display */ 32,
      /* strings */ TFS(&lnet_flags_set_truth),
      /* bitmask */ LDLM_FL_INTENT_ONLY,
      /* blurb   */ "Don't grant lock, just do intent.",
      /* id      */ HFILL
    }
  },
  {
    /* p_id    */ &hf_lustre_ldlm_fl_has_intent,
    /* hfinfo  */ {
      /* name    */ "LDLM_FL_HAS_INTENT",
      /* abbrev  */ "lustre.ldlm_fl_has_intent",
      /* type    */ FT_BOOLEAN,
      /* display */ 32,
      /* strings */ TFS(&lnet_flags_set_truth),
      /* bitmask */ LDLM_FL_HAS_INTENT,
      /* blurb   */ "lock request has intent",
      /* id      */ HFILL
    }
  },
  {
    /* p_id    */ &hf_lustre_ldlm_fl_flock_deadlock,
    /* hfinfo  */ {
      /* name    */ "LDLM_FL_FLOCK_DEADLOCK",
      /* abbrev  */ "lustre.ldlm_fl_flock_deadlock",
      /* type    */ FT_BOOLEAN,
      /* display */ 32,
      /* strings */ TFS(&lnet_flags_set_truth),
      /* bitmask */ LDLM_FL_FLOCK_DEADLOCK,
      /* blurb   */ "flock deadlock detected",
      /* id      */ HFILL
    }
  },
  {
    /* p_id    */ &hf_lustre_ldlm_fl_discard_data,
    /* hfinfo  */ {
      /* name    */ "LDLM_FL_DISCARD_DATA",
      /* abbrev  */ "lustre.ldlm_fl_discard_data",
      /* type    */ FT_BOOLEAN,
      /* display */ 32,
      /* strings */ TFS(&lnet_flags_set_truth),
      /* bitmask */ LDLM_FL_DISCARD_DATA,
      /* blurb   */ "discard (no writeback) on cancel",
      /* id      */ HFILL
    }
  },
  {
    /* p_id    */ &hf_lustre_ldlm_fl_no_timeout,
    /* hfinfo  */ {
      /* name    */ "LDLM_FL_NO_TIMEOUT",
      /* abbrev  */ "lustre.ldlm_fl_no_timeout",
      /* type    */ FT_BOOLEAN,
      /* display */ 32,
      /* strings */ TFS(&lnet_flags_set_truth),
      /* bitmask */ LDLM_FL_NO_TIMEOUT,
      /* blurb   */ "Blocked by group lock - wait indefinitely",
      /* id      */ HFILL
    }
  },
  {
    /* p_id    */ &hf_lustre_ldlm_fl_block_nowait,
    /* hfinfo  */ {
      /* name    */ "LDLM_FL_BLOCK_NOWAIT",
      /* abbrev  */ "lustre.ldlm_fl_block_nowait",
      /* type    */ FT_BOOLEAN,
      /* display */ 32,
      /* strings */ TFS(&lnet_flags_set_truth),
      /* bitmask */ LDLM_FL_BLOCK_NOWAIT,
      /* blurb   */ "Server told not to wait if blocked. For AGL, OST will not send\n"
       "glimpse callback.",
      /* id      */ HFILL
    }
  },
  {
    /* p_id    */ &hf_lustre_ldlm_fl_test_lock,
    /* hfinfo  */ {
      /* name    */ "LDLM_FL_TEST_LOCK",
      /* abbrev  */ "lustre.ldlm_fl_test_lock",
      /* type    */ FT_BOOLEAN,
      /* display */ 32,
      /* strings */ TFS(&lnet_flags_set_truth),
      /* bitmask */ LDLM_FL_TEST_LOCK,
      /* blurb   */ "return blocking lock",
      /* id      */ HFILL
    }
  },
  {
    /* p_id    */ &hf_lustre_ldlm_fl_cancel_on_block,
    /* hfinfo  */ {
      /* name    */ "LDLM_FL_CANCEL_ON_BLOCK",
      /* abbrev  */ "lustre.ldlm_fl_cancel_on_block",
      /* type    */ FT_BOOLEAN,
      /* display */ 32,
      /* strings */ TFS(&lnet_flags_set_truth),
      /* bitmask */ LDLM_FL_CANCEL_ON_BLOCK,
      /* blurb   */ "Immediatelly cancel such locks when they block some other locks. Send\n"
       "cancel notification to original lock holder, but expect no reply. This is\n"
       "for clients (like liblustre) that cannot be expected to reliably response\n"
       "to blocking AST.",
      /* id      */ HFILL
    }
  },
  {
    /* p_id    */ &hf_lustre_ldlm_fl_cos_incompat,
    /* hfinfo  */ {
      /* name    */ "LDLM_FL_COS_INCOMPAT",
      /* abbrev  */ "lustre.ldlm_fl_cos_incompat",
      /* type    */ FT_BOOLEAN,
      /* display */ 32,
      /* strings */ TFS(&lnet_flags_set_truth),
      /* bitmask */ LDLM_FL_COS_INCOMPAT,
      /* blurb   */ "Flag whether a lock is enqueued from a distributed transaction, and the\n"
	"requesting lock mode is PW/EX, if so, it will check compatibility with COS\n"
	"locks, and different from original COS semantic, transactions from the same\n"
	"client is also treated as lock conflict.",
      /* id      */ HFILL
    }
  },
  {
    /* p_id    */ &hf_lustre_ldlm_fl_deny_on_contention,
    /* hfinfo  */ {
      /* name    */ "LDLM_FL_DENY_ON_CONTENTION",
      /* abbrev  */ "lustre.ldlm_fl_deny_on_contention",
      /* type    */ FT_BOOLEAN,
      /* display */ 32,
      /* strings */ TFS(&lnet_flags_set_truth),
      /* bitmask */ LDLM_FL_DENY_ON_CONTENTION,
      /* blurb   */ "measure lock contention and return -EUSERS if locking contention is high",
      /* id      */ HFILL
    }
  },
  {
    /* p_id    */ &hf_lustre_ldlm_fl_ast_discard_data,
    /* hfinfo  */ {
      /* name    */ "LDLM_FL_AST_DISCARD_DATA",
      /* abbrev  */ "lustre.ldlm_fl_ast_discard_data",
      /* type    */ FT_BOOLEAN,
      /* display */ 32,
      /* strings */ TFS(&lnet_flags_set_truth),
      /* bitmask */ LDLM_FL_AST_DISCARD_DATA,
      /* blurb   */ "These are flags that are mapped into the flags and ASTs of blocking locks\n"
       "Add FL_DISCARD to blocking ASTs",
      /* id      */ HFILL
    }
  },

#endif /* WSHARK_INIT_DATA */

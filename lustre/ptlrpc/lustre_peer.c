


struct uuid_nid_data {
        struct list_head head;
        char *uuid;
        __u32 nid;
        __u32 nal;
        ptl_handle_ni_t ni;
};


/* FIXME: This should probably become more elegant than a global linked list */
static struct list_head g_uuid_list;
static spinlock_t       g_uuid_lock;


int lustre_uuid_to_peer(char *uuid, struct lustre_peer *peer)
{
        struct list_head *tmp;

        spin_lock (&g_uuid_lock);

        list_for_each(tmp, &g_uuid_list) {
                struct uuid_nid_data *data =
                        list_entry(tmp, struct uuid_nid_data, head);

                if (strcmp(data->uuid, uuid) == 0) {
                        peer->peer_nid = data->nid;
                        peer->peer_ni = data->ni;

                        spin_unlock (&g_uuid_lock);
                        return 0;
                }
        }

        spin_unlock (&g_uuid_lock);
        return -1;
}

/* delete only one entry if uuid is specified, otherwise delete all */
static int lustre_add_uuid(char *uuid, __u64 nid, __u32 nal)
{
        const ptl_handle_ni_t *nip;
        struct uuid_nid_data *data;
        int rc;
        int nob = strnlen (uuid, PAGE_SIZE) + 1;

        if (nob > PAGE_SIZE)
                return -EINVAL;
        
        nip = lustre_get_ni (nal);
        if (nip == NULL) {
                CERROR("get_ni failed: is the NAL module loaded?\n");
                return -EIO;
        }

        rc = -ENOMEM;
        PORTAL_ALLOC(data, sizeof(*data));
        if (data == NULL)
                goto fail_0;

        PORTAL_ALLOC(data->uuid, nob);
        if (data == NULL)
                goto fail_1;

        memcpy(data->uuid, uuid, nob);
        data->nid = nid;
        data->nal = nal;
        data->ni  = *nip;

        spin_lock (&g_uuid_lock);

        list_add(&data->head, &g_uuid_list);

        spin_unlock (&g_uuid_lock);

        return 0;

 fail_1:
        PORTAL_FREE (data, sizeof (*data));
 fail_0:
        lustre_put_ni (nal);
        return (rc);
}

static int lustre_del_uuid (char *uuid)
{
        struct list_head  deathrow;
        struct list_head *tmp;
        struct list_head *n;
        struct uuid_nid_data *data;
        
        INIT_LIST_HEAD (&deathrow);
        
        spin_lock (&g_uuid_lock);

        list_for_each_safe(tmp, n, &g_uuid_list) {
                data = list_entry(tmp, struct uuid_nid_data, head);

                if (uuid == NULL || strcmp(data->uuid, uuid) == 0) {
                        list_del (&data->head);
                        list_add (&data->head, &deathrow);
                        if (uuid)
                                break;
                }
        }

        spin_unlock (&g_uuid_lock);

        if (list_empty (&deathrow))
                return -EINVAL;
        
        do {
                data = list_entry(deathrow.next, struct uuid_nid_data, head);

                list_del (&data->head);

                lustre_put_ni (data->nal);
                PORTAL_FREE(data->uuid, strlen(data->uuid) + 1);
                PORTAL_FREE(data, sizeof(*data));
        } while (!list_empty (&deathrow));
        
        return 0;
}

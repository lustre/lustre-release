

void commit_add(struct )
{
        struct obd_import *import = commit_uuid2import(rec->  uuid);

        if (!import) {
                CERROR("unaware of OST UUID %s - dorpping\n", rec-> uuid);
                EXIT;
                return;
        }

        spin_lock(&import->llcconf_lock);
        list_add(&rec->  &import);
        spin_unlock(&import->llcconf_lock);
        EXIT;
        return;
}

void commit_confd_conf_import(struct obd_import *import,
                              struct llog_commit_confirm_daemon *lccd)
{
        struct list_head *tmp, *save;


        list_for_each_safe(&import->import_cc_list, tmp, save) {
                struct llog_commit_data *cd;

                if (atomic_read(import->import_cc_count) <=
                    lccd->llcconf_lowwater)
                        break;

                cd = list_entry(tmp, struct llog_commit_data *, llcconf_entry);
                atomic_dec(&import->import_cc_count);
                commit_confd_add_and_fire(cd);
        }
        EXIT;
        return;
}


int commit_confd_main(void *data)
{
        struct llog_commit_confirm_daemon *lccd = data;

        while (1) {
                /* something has happened */
                event_wait();

                if (lccd->flags & LCCD_STOP)
                        break;


                /* lock llccd imporlist */
                spin_lock(&lccd->llcconf_lock);
                list_for_each_safe(&lccd->llcconf_list,   ) {
                        struct obd_import *import;
                        import = list_entry(&lccd->llcconf_list,
                                            struct obd_import,
                                            import_entry);
                        get_import(import);
                        spin_unlock(&lccd->llcconf_lock);
                        if (atomic_read(import->import_cc_count) >
                            lccd->llcconf_highwater)
                                commit_confd_conf_import(import);
                        put_import(import);
                        spin_lock(&lccd->llcconf_lock);

                }
                spin_unlock(&lccd->llcconf_lock);

        }

        lccd->flags = LCCD_STOPPED;
        RETURN(0);
}

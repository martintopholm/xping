FLOW
----

Below is a diagram outlining control flow within xping.c:

    main()                 [xping.c]                      |       [icmp.c]
      |                                                   |
      |---------------------------------------------------|--> probe_setup --------.
      |                                                   |                        |
      |--> target_add ------------------------------------|--> probe_add ---------.|
      |      |                                            |                       ||
      |      '->> target_resolve                          |                       ||
      |             |                                     |                       ||
      |             '->> target_is_resolved --------------|--> probe_resolved     ||
      |                   |                               |      |--> activate <--'|
      |                   '-> ui_update <---,             |      '--> deactivate   |
      |                        ^            |             |                        |
      |->> target_probe_sched  |            |             |                        |
      |         |              |            |             |                        |
      |         '->> target_probe ---------(--------------|--> probe_send          |
      |                                     |             |                        |
      |--> ui_init                         target_mark <--|--- read_packet <<------'
      |                                                   |
      '--> event_base_dispatch                            |


       --> direct execution
       ->> event triggered execution

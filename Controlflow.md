FLOW
----

Below is a diagram outlining control flow within xping.c:

    main()                 [xping.c]                      |       [dnstask.c]
      |                                                   |
      |                                                   | .-> dnstask_new
      |                                                   | |       v
      |                                                   | |       v
      |                                                   | |   sendquery ------.
      |                                                   | |                   |
      |                                                   +--------------------------
      |                                                   | |                   |
      |                                                   | |      [icmp.c]     |
      |                                                   | |                   |
      |---------------------------------------------------|-(-> probe_setup ----(--.
      |                                                   | |                   |  |
      |                                                   | '----.              |  |
      |--> target_add ------------------------------------|--> probe_add -------(-.|
      |                                                   |                     | ||
      |                  target_resolved <----------------|--- resolved <<------' ||
      |                   |                               |      |--> activate <--'|
      |                   '-> ui_update                   |      '--> deactivate   |
      |                        ^    ^                     |                        |
      |->> target_probe_sched  |    |                     |                        |
      |         |              |    |                     |                        |
      |         '->> target_probe --(---------------------|--> probe_send          |
      |                             |                     |                        |
      |--> ui_init                  '-- target_mark <-----|--- read_packet <<------'
      |                                                   |
      '--> event_base_dispatch                            |


       --> direct execution
       ->> event triggered execution

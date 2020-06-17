#ifndef gact_h
#define gact_h

#define GACT_EPOCH 10                         // minutes
#define GACT_EPOCH_SECONDS (GACT_EPOCH*60)    // seconds
#define GACT_EPIDS_PER_DAY (24*60)/GACT_EPOCH

int gact_init(void);
void gact_stop(void);

#endif //dp3t_h

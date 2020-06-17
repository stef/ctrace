#ifndef dp3t_h
#define dp3t_h

#define DP3T_EPOCH 10                         // minutes
#define DP3T_EPOCH_SECONDS (DP3T_EPOCH*60)    // seconds
#define DP3T_EPIDS_PER_DAY (24*60)/DP3T_EPOCH

int dp3t_init(void);
void dp3t_stop(void);

#endif //dp3t_h

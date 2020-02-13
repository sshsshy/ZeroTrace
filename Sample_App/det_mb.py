#Shebang

import os

CWD=os.getcwd()
print(CWD)
LOG_FOLDER=CWD+'/DET_MB_RESULTS/'
if not os.path.exists(LOG_FOLDER):
  os.makedirs(LOG_FOLDER)

EXEC_LOGFILE="exec_log"

#Parameter list

NUM_REQUESTS=100
RECURSION_DATA_SIZE=64
ORAM_TYPE={1}

N=[(lambda x: 2**x)(i) for i in {10,14}]
#N = 1024, 16384,
M={128}
SS=[[100],[8]]
Z =[[3],[3]]
#N=[(lambda x: 2**x)(i) for i in {5,8,10,14,17,20}]
#M={128,256,1024}
#SS=[[100,80,60],[10]]
#Z =[[4,4,4],[3]]
print(N)


# Loop over ORAM Mode
for mode in ORAM_TYPE:
  # Loop over N
  for n in N:
    # Loop over data_size
    for m in M: 
      # Loop over Stash and Z choices
        for s in SS[mode]: 
          for z in Z[mode]:
            print("./testcorrectness "+str(n)+" "+str(NUM_REQUESTS)+" "+str(s)+" "+str(m)+" "+str(RECURSION_DATA_SIZE)+" "+str(mode)+" "+str(z)+" "+LOG_FOLDER)

            command = "./testcorrectness "+str(n)+" "+str(NUM_REQUESTS)+" "+str(s)+" "+str(m)+" "+str(RECURSION_DATA_SIZE)+" "+str(mode)+" "+str(z)+" "+LOG_FOLDER
            os.system(command+" > "+EXEC_LOGFILE)

            with open(EXEC_LOGFILE) as f:
              exec_file = f.read()
              if((("EXP Failed!") in exec_file) or (("STASH OVERFLOW") in exec_file) ):
                print("This experiment failed due to stash overflow or correctness errors\n.")
            # Test if EXEC_LOG threw any Stash Overflows, or failed Experiment, Reject values if so.
            # Invoke Sample_App/testcorrectness <Current Params> 


#Produce result file with comparison table 

#Shebang

import os
import math

RESULT_FILE = "Res1"
CWD=os.getcwd()
print(CWD)
LOG_FOLDER=CWD+'/DET_MB_RESULTS/'
if not os.path.exists(LOG_FOLDER):
  os.makedirs(LOG_FOLDER)

EXEC_LOGFILE="exec_log"

#Parameter list

NUM_REQUESTS=100
RECURSION_DATA_SIZE=64
ORAM_TYPE={0,1}

N=[(lambda x: 2**x)(i) for i in {10,14,17}]
#N=[(lambda x: 2**x)(i) for i in {5,8,10,14,17}]
#N = 1024, 16384,
M={128,256,1024}
SS_Z=[[[150,3],[150,4]],[[16,2],[8,3]]]
PSS=[]
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
      for l in SS_Z[mode]:
        s=l[0]
        z=l[1]
        print("./testcorrectness "+str(n)+" "+str(NUM_REQUESTS)+" "+str(s)+" "+str(m)+" "+str(RECURSION_DATA_SIZE)+" "+str(mode)+" "+str(z)+" "+LOG_FOLDER)
        print LOG_FOLDER;
             
        command = "./testcorrectness "+str(n)+" "+str(NUM_REQUESTS)+" "+str(s)+" "+str(m)+" "+str(RECURSION_DATA_SIZE)+" "+str(mode)+" "+str(z)+" "+LOG_FOLDER
        os.system(command+" > "+EXEC_LOGFILE)

        with open(EXEC_LOGFILE) as f:
          exec_file = f.read()
          if((("EXP Failed!") in exec_file) or (("STASH OVERFLOW") in exec_file) ):
            print("This experiment failed due to stash overflow or correctness errors\n.")
            # Test if EXEC_LOG threw any Stash Overflows, or failed Experiment, Reject values if so.
            if(mode==0):
              prefix='PO'
            elif(mode==1):
              prefix='CO'
            LOG_FILE_NAME=prefix+'_'+str(n)+'_'+str(m)+'_'+str(s)+'_'+str(z)+'_'+str(NUM_REQUESTS)
            LOG_FILE=LOG_FOLDER+LOG_FILE_NAME
            LOG_FILE_AVG=LOG_FILE+"_AVG" 
            LOG_FILE_STD=LOG_FILE+"_STD" 
            # Delete result file, so that in the RESULT_FILE generator we fill with NA values.
            if(os.path.exists(LOG_FILE)):
              os.remove(LOG_FILE)
              
            if(os.path.exists(LOG_FILE_AVG)):
              os.remove(LOG_FILE_AVG)

            if(os.path.exists(LOG_FILE_STD)):
              os.remove(LOG_FILE_STD)
#print(SS_New)
#Use PSS for pathOram stash sizes
#Produce result file with comparison table 

# Produce CSV file:
# ORAM | N | datasize | stashsize | Z | Posmap | Download | FetchBlock | Eviction | Upload | Total |

mstr = ''
prefix = ''
with open(RESULT_FILE,'w') as rf:
  rf.write("ORAM, N, datasize, stashsize, Z, PositionMap Time, Download Path Time, Fetch Block Time, Eviction Time, Upload Path Time, Total Time\n")
  for mode in ORAM_TYPE:
    # Loop over N
    if (mode==0):
      mstr = 'Path'
      prefix = 'PO'
    elif (mode==1):
      mstr = 'Circuit'
      prefix = 'CO'
    for n in N:
      # Loop over data_size
      for m in M:
        for l in SS_Z[mode]:
          #z=l[1]
          #s=PSS[PSS_ctr]
          s=l[0]
          z=l[1]
           
          #Extract details from LOG_FILE_AVG 
          LOG_FILE_NAME=prefix+'_'+str(n)+'_'+str(m)+'_'+str(s)+'_'+str(z)+'_'+str(NUM_REQUESTS)
          LOG_FILE=LOG_FOLDER+LOG_FILE_NAME
          LOG_FILE_AVG=LOG_FILE+"_AVG" 

          RESULT_LINE_PARAMS=mstr+','+str(n)+','+str(m)+','+str(s)+','+str(z)+','
          RESULT_LINE_VALUES=''
          if(os.path.exists(LOG_FILE_AVG)):
            with open(LOG_FILE_AVG) as f:
              line = f.readline()
              line = line.strip()
              words = line.split(',')
              RESULT_LINE_VALUES=words[0].strip()+','+words[1].strip()+','+words[2].strip()+','+words[3].strip()+','+words[4].strip()+','+ words[5].strip()
              RESULT_LINE=RESULT_LINE_PARAMS+RESULT_LINE_VALUES+'\n'
          else:
            RESULT_LINE_VALUES='NA,NA,NA,NA,NA,NA' 
          
          RESULT_LINE=RESULT_LINE_PARAMS+RESULT_LINE_VALUES+'\n'
          rf.write(RESULT_LINE)


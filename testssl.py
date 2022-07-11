from datetime import datetime
import subprocess

class testssl:


    def __init__(self, target) -> None:
        current_time = int(datetime.now().timestamp())
        self.filename = '/tmp/'+target+str(current_time)+'.json'
        subprocess.run(['testssl', '-q', '-P', '-p', '-e', '--jsonfile-pretty', self.filename, target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        #os.system('testssl -q -P -p -e --jsonfile-pretty logs/'+self.filename+' '+target)
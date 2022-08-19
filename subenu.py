import json,argparse,os,sys,time,aiohttp,asyncio,requests
from multiprocessing import Pool
global lst,domain,httpurls,httpstat,start_time,home,lster
httpurls = []
httpstat=[]
lster = []

value = dict(os.environ)
home = value["HOMEDRIVE"]+value["HOMEPATH"]

def banner():
    global B,R,W
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white
    import win_unicode_console , colorama
    win_unicode_console.enable()
    colorama.init()


    banner = """
    ███████╗██╗   ██╗██████╗ ███████╗███╗   ██╗██╗   ██╗
    ██╔════╝██║   ██║██╔══██╗██╔════╝████╗  ██║██║   ██║
    ███████╗██║   ██║██████╔╝█████╗  ██╔██╗ ██║██║   ██║
    ╚════██║██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║██║   ██║
    ███████║╚██████╔╝██████╔╝███████╗██║ ╚████║╚██████╔╝
    ╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ 
    ----------------------------------------------------
    Code Written By: Tanker2020"""

    print(R+banner)
    print(B+"")

def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -d google.com")
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Domain name to enumerate it's subdomains", required=True)
    parser.add_argument('-w', '--wordlist', help="File Path for common Subdomains wordlist")
    parser.add_argument('-p', '--ports', help='Scan the found subdomains against specified tcp ports')
    parser.add_argument('-ht', '--aiohttp', help='enable if you have fast computer(might take a while based on enabled time); this will use http requests to check if site exists', action= 'store_true')
    parser.add_argument('-t', '--httptime', help='max time for http method to take in seconds;max  (might take less time if wordlist is smaller)',type=int,default=120)
    parser.add_argument('-o', '--output', help='Save the results of each method to a different text file in the current directory',action='store_true')
    return parser.parse_args()

def argcall():
    global args
    try:
        args = parse_args()
    except KeyboardInterrupt:
        SystemExit

def wordlist():
    if args.wordlist == None:
        wordlistpath = fr"{home}\Documents\wordlistsub.txt"
    else:
        wordlistpath = args.wordlist
    return wordlistpath



def readfiles(wordlistpath):
    with open(fr"{wordlistpath}","r") as file:
        sub = file.readlines()
        for i in sub:
            lster.append(i.strip())
    file.close()


start_time = time.time()

async def get_stat(session, url,loop):
    timeout = args.httptime
    try:
        async with session.request(method="HEAD",url=url,allow_redirects=False,timeout=timeout) as resp:
            statuscode = resp.status
            if statuscode != None:
                httpstat.append(statuscode)
                httpurls.append(url)
                
    except aiohttp.ClientConnectorError:
        print("Doesn't exist| ",url)
    except asyncio.TimeoutError:
            print(url," timed out :(")
            task = asyncio.all_tasks(loop=loop)
            for tasks in task:
                tasks.cancel()
    except UnicodeError:
        print("Unicode error| ",url)
    except aiohttp.InvalidURL:
        print(url," invalid url")

async def bound_fetch(sem, session, url,loop):
    async with sem:
        await get_stat(session, url,loop)

async def main(loop):
    domain = args.domain
    print(R+"======================================")
    print("Trying http connection method first...")
    print("======================================")
    print(B+"")
    sem = asyncio.Semaphore(15)
    async with aiohttp.ClientSession() as session:
        task = []
        for i in lster:
            url = f"https://{i}.{domain}"
            task.append(asyncio.ensure_future(bound_fetch(sem,session, url,loop)))

        try:
            stats = await asyncio.gather(*task)
        except asyncio.CancelledError:
            print(R+"```````````````````````````````````````````````````````````````")
            print("Shutdown of HTTP Method initialized ...")
            print(f"{args.httptime} second(s) timer has been up, Stopping method")
            print("Next time use shorter wordlist or better cpu")
            print("Shutdown complete ...")
            print("```````````````````````````````````````````````````````````````")
            print(B+"")
        for g in range(len(httpurls)):
            print("Url| ",httpurls[g]," StatusCode: ",httpstat[g])

def starthttp():
    readfiles(wordlist())
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main(loop))
    loop.close()
    print("--- %s seconds ---" % (time.time() - start_time))
    if args.output == True:
        outputhttp()

def outputhttp():
    try:
        os.remove(fr"{sys.argv[0]}\http.txt")
    except FileNotFoundError:
        pass
    with open("http.txt","a") as file:
        for g in range(len(httpurls)):
            file.write(f"Url| {httpurls[g]} StatusCode: {httpstat[g]}")
            file.write("\n")
    file.close()

def crtsh():
    print(R+"\n=================================================")
    print("Trying crt.sh SSL/TLS Cerfications method next...")
    print("=================================================")
    print(B+"\n")
    crtlst=[]
    try:    
        os.remove(fr"{sys.argv[0]}\crt.txt")
    except FileNotFoundError:
        pass
    while True:
        try:
            result = requests.get(f"https://crt.sh/?q={args.domain}&output=json").json()
            try:
                for i in range(len(result)-1):
                    with open("crt.txt","a") as file:
                        file.write(result[i]['name_value'])
                        file.write("\n")
                    change = list(result[i]['name_value'])
                    for l in range(len(change)):
                        if change[l-1] == "\n":
                            change.remove(change[l-1])
                            change.insert(l-1," ")
                    print("url(s) | "+result[i]['name_value'])
                    print("\n")
                    crtlst.append("".join(change))
                break
            except IndexError:
                print("No Certificates Found but domain exists :/")
                time.sleep(2)
                break
        except requests.exceptions.ConnectionError:
            continue
        except json.decoder.JSONDecodeError:
            print("No Certificates Found :(")
            time.sleep(2)
            break
    return crtlst

def cloudflare():
    print(R+"\n=================================================")
    print("Trying Cloudflare API method next...")
    print("=================================================")
    print(B+"\n")
    cldlst = []
    
    

def scan():
    pass



if __name__ == "__main__":
    banner()
    argcall()
    if args.aiohttp == True:
        starthttp()
        time.sleep(15)
    crtsh()

print(W+"")
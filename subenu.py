import json,argparse,os,sys,time,aiohttp,asyncio,requests
from multiprocessing import Pool
global lst,domain,urls,stat,start_time,home
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
    parser.add_argument('-ht', '--aiohttp', help='enable if you have fast computer(might take 15 mins); this will use http requests to check if site exists', action= 'store_true')
    parser.add_argument('-t', '--httptime', help='max time for http method to take in seconds;max 500 (might take less time if wordlist is smaller)',type=int,default=900)
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
        wordlistpath = r"C:\Users\Nish\Documents\wordlistsub.txt"
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

async def get_stat(session, url):
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
            pending = asyncio.all_tasks()

            for task in pending:
                task.cancel()
    except UnicodeError:
        print("Unicode error| ",url)
    except aiohttp.InvalidURL:
        print(url," invalid url")

async def main():
    domain = args.domain
    print(R+"======================================")
    print("Trying http connection method first...")
    print("======================================")
    print(B+"")

    async with aiohttp.ClientSession() as session:
        task = []
        for i in range(len(lster)):
            url = f"https://{lster[i]}.{domain}"
            task.append(asyncio.ensure_future(get_stat(session, url)))

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
        for g in range(len(urls)):
            print("Url| ",urls[g]," StatusCode: ",stat[g])

def starthttp():
    readfiles(wordlist())
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()
    print("--- %s seconds ---" % (time.time() - start_time))
    if args.output == True:
        outputhttp()

def outputhttp():
    with open("http.txt","a") as file:
        for g in range(len(urls)):
            file.write("Url| ",urls[g]," StatusCode: ",stat[g])
    file.close()

def crtsh():
    print(R+"\n=================================================")
    print("Trying crt.sh SSL/TLS Cerfications method next...")
    print("=================================================")
    print(B+"\n")
    crtlst=[]
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
                    print(result[i]['name_value'])
                    print("\n")
                    crtlst.append("".join(change))
                break
            except IndexError:
                print("No Certificates Found but domain exists :/")
                break
        except requests.exceptions.ConnectionError:
            continue
        except json.decoder.JSONDecodeError:
            print("No Certificates Found :(")
            break
    return crtlst


    
    

def scan():
    pass



if __name__ == "__main__":
    banner()
    argcall()
    if args.aiohttp == True:
        starthttp()
    crtsh()

print(W+"")
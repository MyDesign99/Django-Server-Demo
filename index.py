#! E:/xampp/python312/python.exe

import md99auth
import os

# ------- Function: Strip the Route -----------
def getAuthRoute (origPath):
    parts = origPath.split('/');
    start = 0
    if len(parts[0]) == 0:
        start = 1
    if len(parts) < start+3:
        return ["error", 0]
    if parts[start].lower() != "getauthurl":
        return ["error", 0]
        
    return [parts[start+1], parts[start+2]]

print("Content-Type: text/html\n")

#---------------------------------------
def startHere_1 ():
   
    # ------- Section: Route Detection -----------
    path = os.environ["REQUEST_URI"]
    parts = path.split('/');
    authParams = getAuthRoute (path)

    if authParams[0] == "error":
        print ("Invalid Route")
        print ("<br />")
        print (authParams)
        return

    print ("Requesting the URL for")
    print (" - Value: " + str(authParams[0]))
    print (" - Asset: " + authParams[1])
        
    publicKey = ""
    secretKey = ""
    value     = authParams[0]
    assetName = authParams[1]
    fullToken = md99auth.getImageURL (publicKey, secretKey, value, assetName)

    if fullToken["success"] == False:
        print ("<br />")
        print ("Request Failed: " + fullToken["err_msg"])
        return

    print ("<br />")
    print ("Image URL:")
    print ("<br />")
    print (fullToken["url"])

#---------------------------------------
def startHere_2 ():
   
    publicKey = ""
    secretKey = ""
    fullToken = md99auth.getImageURLfromPost (publicKey, secretKey)

    if fullToken["success"] == False:
        print ("<br />")
        print ("Request Failed: " + fullToken["err_msg"])
        return

    print ("<br />")
    print ("Image URL:")
    print ("<br />")
    print (fullToken["url"])

#---------------------------------------

startHere_2()



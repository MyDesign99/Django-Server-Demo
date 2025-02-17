import sys
import base64
import json
import hmac
import hashlib
import re
from urllib import request, parse
import os.path
import time

gRemoteUrl = "https://mydesign99.com/"
gErrImg    = "images/image_not_found.png"

# ------- Function: format the Asset Name to be correctly URL encoded -----------
def stripAssetName (name):
    name = name.replace (" " , "-")                 # replace spaces with dashes
    name = name.lower()                             # change to all lower case
    name = re.sub ('[^-a-z0-9_]', '', name)         # keep only dash, underscore, letters and numbers
    name = re.sub ('\-+', '-', name)                # remove duplicate dashes
    name = name.strip ("-")                         # trim dashes
    
    return name;
# ------- Function: format the return data -----------
def formatError (errMsg):
    imgUrl = gRemoteUrl + gErrImg
    retObj = {"success": False, "err_msg" : errMsg, "url" : imgUrl}
    return retObj
# ------- Function: format the return data -----------
def formatSuccess (clientID, token, value, asset):
    if type(clientID) != 'str':
        clientID = str (clientID)
    if type(token) != 'str':
        token = str (token)
    if type(value) != 'str':
        value = str (value)
    if type(asset) != 'str':
        asset = str (asset)
        
    asset = stripAssetName (asset)
    
    imgUrl = gRemoteUrl + "get/" + clientID + "/" + token + "/" + value + "/" + asset + ".png"
    retObj = {"success": True, "err_msg" : "", "url" : imgUrl}
    return retObj
# ------- Function: Write JSON array to file as string -----------
def stringifyNoSpaces (srcArray):
    asJsonStr = json.dumps (srcArray)
    return asJsonStr;

# ------- Function: JSON array to string with no spaces -----------
def writeTokenDataToFile (srcArray):
    asJsonStr = json.dumps (srcArray, separators=(',', ':'))
    with open('md99_data.txt', 'w+') as fileObj:
        fileObj.write (asJsonStr)
# ------- Function: JSON array to string with no spaces -----------
def readTokenDataFromFile ():
    if not os.path.exists ('md99_data.txt'):
        return None
    with open ('md99_data.txt', 'r') as fileObj:
        asJsonStr = fileObj.read ()
        try:
            asArray = json.loads (asJsonStr)
        except:
            print ("Invalid JSON in cache text file")
            return None
        if 'token' not in asArray:
            return None
        if 'expires' not in asArray:
            return None
        curTime = int(time.time())
        expires = int(asArray['expires'])
        if curTime > expires:
            return None
        return asArray['token']

# ------- Function: standard array converted to a Base64-encoded string -----------
def arrayTo64 (srcAr):
    asJsonStr = stringifyNoSpaces (srcAr)
    asBytes   = bytes (asJsonStr, 'utf-8')
    b64Bytes  = base64.b64encode (asBytes)
    b64Str    = str (b64Bytes.decode ('utf-8'))
    b64Str    = b64Str.replace("+", "-")
    b64Str    = b64Str.replace("/", "_")		
    b64Str    = b64Str.strip ('=');
    return b64Str
# ------- Function -----------
def _64ToArray (_64Str):
    asBytes = base64.b64decode (_64str)
    asJsonStr = asBytes.decode ('utf-8')
    return json.loads (asJsonStr)
# ------- Function: build the full JWT token as a string -----------
def buildJWT (payloadAsAr, secret):
    secret = bytes (secret, 'utf-8')
    hdrAr  = {"alg" : "HS256", "typ" : "JWT"}

    hdr64Str    = arrayTo64 (hdrAr)
    pay64Str    = arrayTo64 (payloadAsAr)
    
    full64Str   = hdr64Str + "." + pay64Str
    full64Bytes = bytes (full64Str, 'utf-8')
    dig = hmac.new (secret, full64Bytes, hashlib.sha256).digest()

    sign64Str = str (base64.b64encode(dig).decode())
    sign64Str = sign64Str.replace("+", "-")
    sign64Str = sign64Str.replace("/", "_")		
    sign64Str = sign64Str.strip ('=');
    
    return hdr64Str + "." + pay64Str + "." + sign64Str

# ------- Function: read and process the reply from the remote server -----------
def parseTokenFromResult (replyJson, clientID, value, asset):
    #print ("<br />JSON reply from server<br />")
    #print (replyJson)
    
    try:
        replyArray = json.loads (replyJson)
    except:
        return formatError ("Could not process the reply (invalid json)")

    if 'is_success' not in replyArray:
        return formatError ("Could not process the reply (missing success)")
        
    if replyArray['is_success'] != '1'  and  replyArray['is_success'] != 1:
        if 'err_msg' not in replyArray:
            return formatError ("Could not process the reply (missing message)")
        return formatError ("The server returned an error: " + replyArray['err_msg'])

    if 'data' not in replyArray:
        return formatError ("Could not process the reply (missing data)")

    dataArray = replyArray['data']
    if 'token' not in dataArray:
        return formatError ("Could not process the reply (missing token)")

    token = dataArray['token']

    writeTokenDataToFile (dataArray)
    
    return formatSuccess (clientID, token, value, asset)

# ------- Function: main entry point #2into this module -----------
def getImageURL (publicKey, secretKey, value, asset):
    storedToken = readTokenDataFromFile ()
    if not storedToken == None:
        print ("<br />Found Token in Local file<br />")
        return formatSuccess (publicKey, storedToken, value, asset)

    print ("<br />No token found in Local file<br />")
    payloadAr = {'client_id': publicKey}
    remoteUrl = gRemoteUrl + "api/get/authtoken"
    fullJwt   = buildJWT (payloadAr, secretKey)

    postParams = {'jwt': fullJwt}

    encodedData = parse.urlencode (postParams).encode()
    fullReq     = request.Request (remoteUrl, encodedData)
    print ("*** md99 *** Ready to make http request: " + remoteUrl)
    reply       = request.urlopen (fullReq)
    charset     = reply.info().get_content_charset()
    content     = reply.read().decode(charset)
    
    token = parseTokenFromResult (content, publicKey, value, asset)
    return token

# ------- Function: main entry point #1 into this module -----------
def getImageURLfromPost (publicKey, secretKey):
    postStr = str (sys.stdin.read())
    try:
        postArray = json.loads (postStr)
    except:
        return formatError ("Could not process the post data (invalid json)")

    if 'asset_name' in postArray  and  'value' in postArray:
        value     = postArray['value']
        assetName = postArray['asset_name']
        return getImageURL (publicKey, secretKey, value, assetName)

    if len (postArray) == 1:
        postArray = postArray[0]
        if 'asset_name' in postArray  and  'value' in postArray:
            value     = postArray['value']
            assetName = postArray['asset_name']
            return getImageURL (publicKey, secretKey, value, assetName)
            
    return formatError ("Could not find the required value in the post data")


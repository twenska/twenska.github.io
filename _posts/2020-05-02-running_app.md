---
title: "Faking all the runs - Reverse the API of an Android Running App"
excerpt_separator: "<!--more-->"
categories:
  - Blog
tags:
  - Reverse Engineering
  - Frida
  - Android
  - Python
---
During the Corona quarantine my amateur football coach made me and my teammates compete in a running competition. Runs are tracked with a mobile phone app. 
I used this as an opportunity to take a look at the app with the target to reverse the network protocol between the app and the backend. 
With that information I want to write a script that will automatically create a run, push me in the rankings of my football team and cheat the system.

# First look at the app
The app in question is the [Adidas Running App](https://play.google.com/store/apps/details?id=com.runtastic.android&hl=en) (former Runtastic; Adidas seems to have bought this app and rebranded it). I will use a rooted Redmi Note 5 running Lineage OS to conduct all testing. The app is available for both - iOS and Android - but as we only want to reverse the network communication it should make little difference what OS to try on.

To take a first look on the network traffic we will create a proxy on the mobile phone. This will get the application traffic to my Linux workstation where we can conduct further analysis. (Sometimes apps won't use the proxy. This depends on the app settings. In this case the app will route it's traffic through the configured proxy, so no need for a VPN setup).
On my workstation I have [Burp proxy](https://portswigger.net/burp) listening and intercepting traffic. The app will most likely use a HTTPs connection so we have to import the self-signed Burp root CA certificate on the Android phone. This way the app/phone will trust it. (One should probably remove this certificate after testing/experimenting)

After doing this basic setup we can start the app. It will give us an error message that there is a problem with our network connection. Assuming our proxy config is correct, this is most likely because the app uses [Certificate pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning). This technique ensures that the certificate presented in the SSL/TLS Handshake is not only valid under the normal criteria, (e.g. signed by trusted root, not expired, issued for right domain) but also matches a hard coded fingerprint. This is done to prevent traffic interception (like we want to do) and can be considered a security and anti-reversing feature.

To get analyse the network communication we will have to find a way around this obstacle.

# Circumventing Certificate Pinning
We will use instrumentation to disable the certificate pinning in the running app. A very useful tool to do instrumentation on nearly any platform is [Frida](https://frida.re/). We can inject frida into the running app and then hook the functions used for the certificate pinning. There is however a minor annoyance in this approach as there are a few ways for an app to implement cert pinning. Depending on used network APIs and/or clients there are different functions used. (I will leave the specifics to someone with experience in Android programming...) As I don't want to research for the way this specific app makes certificate pinning work, we won't use native Frida. Instead we will use a tool called [Objection.](https://github.com/sensepost/objection) Objection is based on frida and has out-of-the box support for disabling SSL/Certificate pinning.

To use objection we first have to get frida running. The best reference for this is the [official documentation](https://frida.re/docs/android/) on the Frida website. The setup should look something like this:

<figure>
	<a href="https://raw.githubusercontent.com/twenska/twenska.github.io/master/assets/images/runningApp_frida_setup.png"><img src="https://raw.githubusercontent.com/twenska/twenska.github.io/master/assets/images/runningApp_frida_setup.png"></a>
</figure>

After setting up Frida we can search for our app and use objection to disable the cert pinning:
<figure>
	<a href="https://raw.githubusercontent.com/twenska/twenska.github.io/master/assets/images/runningApp_objection_disable_pinning.png"><img src="https://raw.githubusercontent.com/twenska/twenska.github.io/master/assets/images/runningApp_objection_disable_pinning.png"></a>
</figure>

Now we can surf around in the app and see the intercepted communication in Burp:
<figure>
	<a href="https://raw.githubusercontent.com/twenska/twenska.github.io/master/assets/images/runningApp_first_intercepted_connections.png"><img src="https://raw.githubusercontent.com/twenska/twenska.github.io/master/assets/images/runningApp_first_intercepted_connections.png"></a>
</figure>

# Analysing the network traffic
With the proper interception of the network traffic we can now analyse the app. We could just play around and see what happens but before that lets take a moment to think aboutour target: We want to create fake runs in the app. Based on this and a basic understanding of how stuff like this works we can make an educated guess what we will need to see to reach our target:
  1. Authenticate with a valid account
  2. Create data for the run
  3. Post the run information to the backend
  4. Optional: Parse sepcial return values
  5. Optional: Logout/Unvalidate access tokens

So let's get our hands dirty. We will open the app, login, start a run, walk around a little bit and then end the run. We will have to do all of that while our proxy is intercepting the network connection. After, we can see following POST requests in Burp (marked the relevant and deleted some of the not so relevant):
<figure>
	<a href="https://raw.githubusercontent.com/twenska/twenska.github.io/master/assets/images/runningApp_relevant_intercepted_connections.png"><img src="https://raw.githubusercontent.com/twenska/twenska.github.io/master/assets/images/runningApp_relevant_intercepted_connections.png"></a>
</figure>

The API endpoints are named after their function and are all hosted at the domain `appws.runtastic.com`. To get to our target we will have to analyze the POST requests to:
**/webapps/services/auth/v2/login/runtastic**
**/webapps/services/runsessions/v3/sync**

The first one is the login and the second one the post of a finished run. Some of the other APIs would look juicy, but we are not here to find bugs/vulnerabilities (and also not allowed, as I dont think they have a Bug Bounty program). We just want to use the APIs as they are intended, just not with the app provided by the developer. ;)

The login request looks like this:

{% highlight javascript linenos %}
POST /webapps/services/auth/v2/login/runtastic HTTP/1.1
Content-Encoding: gzip
X-Date: 2020.05.02 12:46:20
X-Device-Name: Redmi Note 5 Pro
X-Device-Vendor: Xiaomi
accept: application/json;case=snake;time_format=ms
X-App-Key: com.runtastic.android
X-Device-Token: REDACTED
X-Locale: en-US
X-Auth-Token: cd0a1a694056147f6c84c6dbe226c0e741e67ce2
X-Device-Firmware: Android 8.1.0
X-Screen-Pixels: 1080x2016
X-App-Version: 11.0
X-Carrier: 
Content-Type: application/json; charset=utf-8
Host: appws.runtastic.com
Connection: close
Accept-Encoding: gzip, deflate
Cookie: JSESSIONID=tf-prd-glassfish-server-003~""; tf-trinidad=tf-prd-goals-server-001
User-Agent: okhttp/3.14.7
X-NewRelic-ID: Vw4AU1VACwMAXVJSBwQ=
Content-Length: 288

      mKO0ÿ»q G%(ÐJ{ÛØÛÊ4¶SÇªªÿÄÎÎì·sbª6èâD³[àæ(`Y8 à6­@å¨j[aÆ¥,Ò¡B­Ò"O , TüÒæ¨F"JW7R?î9WÉZå¸¥}8LóÍ!ßoÄþZ1[?4KôËôýIùõªÛ» ..
®¶ýòAÓÚ>1å;ÃñÖëÞ^ÎÉ@¦&a»6b°àç×;û}A«½ºÏ¢#Õbø4
g¸3ÞÑRãº:Åw}ò®¾ÁËCm;þZØk?.è¨#¾Ù¿ßÏÇx¦cm  
{% endhighlight %}

The first interesting bit is in the HTTP Headers of the request. There are a few uncommon headers and it seems that the header `X-Auth-Token` could cause us some problems (custom authentication always sucks). If we change or omit the value of it in one of the requests we get a HTTP 403 Forbidden error message. We will need to reverse how this token is genrated later
The payload seems to be binary. The header `Content-Encoding` tells us that it is gzipped. Using the Decoder feature of Burp we can unzip the payload and get JSON:

{% highlight javascript linenos %}
{"clientId":"REDACTED","clientSecret":"REDACTED","grantType":"password","me":{"agbAccepted":true,"birthday":"1987-04-24","countryCode":"VA","email":"mustermann22@gmx.de","firstName":"Max","gender":"F","lastName":"Mustermann","locale":"en","serviceRegion":"default","timeZone":"Europe/Berlin"},"password":"REDACTED","username":"mustermann22@gmx.de"}
{% endhighlight %}
The only things not immediately clear are the clientID and clientSecret field. These seem to be random generated numbers.

The answer to a valid login request is a HTTP 200 with a JSON body like this:
{% highlight javascript linenos %}
{"accessToken":"REDACTED","expiresIn":2678399,"tokenType":"Bearer","me":{"agbAccepted":true,"avatarUrl":"https://dxp86gw5pke1r.cloudfront.net/default___default_avatar_female.jpg","birthday":546220800000,"countryCode":"VA","email":"mustermann22@gmx.de","firstName":"Max","gender":"F","guid":"KGMCDRMGZBJHU6VP","height":1.65,"id":159789090,"isDefaultHeight":true,"isDefaultWeight":true,"lastName":"Mustermann","uidt":"d2b49bb2006a66a6bddbf02b3f973d5a9dab3135","unit":0,"weight":60.0}}
{% endhighlight %}
We can see that there is a Bearer Authorization token in all following requests. The token we get here is equal to one used in later Authroization headers. The rest of the field seems not important to us, its mostly information about the authorized user. (I created a test user and let him live in the Vatican...)

The POST request for posting our simulated run has the additional Authorization header and following JSON payload:

{% highlight javascript linenos %}
{"perPage":50,"syncedUntil":1588416404000,"uploadSessions":[{"additionalInfoData":{"cadenceAvg":0,"cadenceMax":0,"feelingId":-1,"notes":"","pulseAvg":0,"pulseMax":0,"surfaceId":-1,"weatherId":-1},"calories":25,"clientId":"5","distance":300,"duration":308000,"elevationGain":0,"elevationLoss":0,"endTime":1588413165851,"extendedData":{"dehydrationVolume":37},"gpsElevationGain":0,"gpsElevationLoss":0,"heartRateData":{"avg":0,"max":0},"manual":true,"oldSessionId":0,"pause":0,"records":{"achievements":{"fastest10k":"none","fastest3Mi":"none","fastest5k":"none","fastestHalfMarathon":"none","fastestKm":"none","fastestMarathon":"none","fastestMi":"none"},"positions":{"fastest10k":"none","fastest3Mi":"none","fastest5k":"none","fastestHalfMarathon":"none","fastestKm":"none","fastestMarathon":"none","fastestMi":"none"}},"speedData":{"avg":3.5064933,"max":0.0},"sportTypeId":1,"startTime":1588412857851}]}
{% endhighlight %}
You can decide in the app if you would like to send GPS data or not. For the simualtion I decided not to, else we would probably see a lot more data here. We can still see a lot of values, but most of them seem empty or defaults and probaly not relevant for us. We will manipulate distance, duration, endTime and startTime and leave the rest.
The response to this request is a HTTP 200 with some additional data the app will use to display information.

With our collected information on the layout of the two POST Requests we can write a quick python script that will try to get authorized with username and password. We will create a recent `X-Date` header and use a test user to login. A quick script could look like this:

{% highlight javascript linenos %}
import requests
import gzip

username = "Testuser"
password = "Testpassword"

#generate X-Date
x_date = str(datetime.datetime.now())
x_date=x_date.split('.')[0]
x_date=x_date.replace('-','.')

headers = {'Content-Encoding': 'gzip', 'X-Date': x_date,'X-Device-Name': 'Redmi Note 5 Pro', 'X-Device-Vendor': 'Xiaomi', 'X-App-Key': 'com.runtastic.android', 'X-Device-Token': '5c9d5682-5395-4a82-afbf-d6c9a63f3e4a', 'X-Locale': 'en-US',  'X-Auth-Token': '54464f94dd3011b4b6c965e111fbd70310cc2f6a','X-Device-Firmware': 'Android 8.1.0', 'Content-Type': 'application/json; charset=utf-8', 'Host': 'appws.runtastic.com', 'User-Agent': 'okhttp/3.14.7','X-NewRelic-ID': 'Vw4AU1VACwMAXVJSBwQ='}
payload = '{"clientId":"REDACTED","clientSecret":"REDACTED","grantType":"password","me":{"countryCode":"DE","email":"'+username+'","locale":"en","serviceRegion":"default","timeZone":"Europe/Berlin"},"password":"'+password+'","username":"'+username+'"}'
#https://stackoverflow.com/questions/8506897/how-do-i-gzip-compress-a-string-in-python
gzip_payload= gzip.compress(bytes(payload,'utf-8'))

login_url = 'https://appws.runtastic.com/webapps/services/auth/v2/login/runtastic'
r = requests.post(login_url, data=gzip_payload, headers=headers)
print(r)
{% endhighlight %}

The script will return a `HTTP 403 Forbidden` error. If we would use the app to login with false credentials we would get a `HTTP 401 Unauthorized` error, so the 403 isn't related to the credentials. It is most likely that the `X-Auth-Token` is responsible for our error. The values is always different in each request but we just copied it. We can validate this by intercepting valid requests made from the app with burp. Then we change up different header values. We get the 403 error if we change `X-Auth-Token`, `X-Date` or `X-App-ID`. These headers seem to be related and validated in the backend of the script. We have to figure out how the custom headers are created:

The change of `X-Auth-Token` in each request is due to the relation to the `X-Date` header that always changes relevant to the time. If we look at the valid values from the app we can make an educated guess that this could be a hash of some sort. One thing about hashes is that they have a constant length (atleast cryptographic hashes have). The most prevalent hashes usend in the internet are most likely MD5, SHA1 and SHA2 (and maybe some others). We can lookup the fixed lengths of them and find a match of our value with the length of SHA1. We still need to know which values are hashed each time. We already found out that `X-Date` and `X-App-ID` are involved. We can predict both becaues one represents time and the other alway has the same value (atleast on the Android app) - com.runtastic.android
Still we have very limited information about how the hash is built, as there seems to be no obvious combination of the `X-Date` and `X-App-Key` that form the resulting SHA-1 hash.
It's time to use more advanced static and/or dynamic approaches.

# Reversing & Hooking the application
We use the tool [jadx](https://github.com/skylot/jadx) to take a look at the apk file of the app.
We cam downloade the apk file with the adb pull command from my phone. Next we start jadx-gui and open the apk inside. Using the search function to look for the strings we already knew had to be somewhere in the app (e.g. X-Auth-Token, X-Date or X-App-ID) we find `X-Auth-Token` in a call to `hashMap.put("X-Auth-Token", str2);`. In the same class we see a few more of the headers we know from the request. The class is probably used to prepare the custom headers before the request. The variable str2 will have our X-Auth-Token, so we have to look at where it is set.
The call involving X-Auth-Token is in following function:
{% highlight javascript linenos %}
public Map<String, String> a(boolean z, @Nullable String str) {
        String str2;
        HashMap hashMap = new HashMap(this.a);
        if (!(this.b != null)) {
            return hashMap;
        }
        d dVar = this.b;
        String str3 = dVar.a;
        String str4 = dVar.b;
        Date date = new Date();
        hashMap.put("X-Date", ((DateFormat) p.b.get()).format(date));
        StringBuilder sb = new StringBuilder();
        sb.append(MultipartContent.TWO_DASHES);
        i.d.b.a.a.a(sb, str3, MultipartContent.TWO_DASHES, str4, MultipartContent.TWO_DASHES);
        sb.append(((DateFormat) p.b.get()).format(date));
        sb.append(MultipartContent.TWO_DASHES);
        String sb2 = sb.toString();
        try {
            MessageDigest messageDigest = (MessageDigest) p.c.get();
            byte[] bytes = sb2.getBytes("UTF8");
            messageDigest.reset();
            messageDigest.update(bytes);
            byte[] digest = messageDigest.digest();
            if (digest == null) {
                str2 = null;
            } else {
                StringBuffer stringBuffer = new StringBuffer();
                for (int i2 = 0; i2 < digest.length; i2++) {
                    byte b2 = (digest[i2] >>> 4) & 15;
                    for (int i3 = 0; i3 < 2; i3++) {
                        if (b2 < 0 || b2 > 9) {
                            stringBuffer.append((char) ((b2 - 10) + 97));
                        } else {
                            stringBuffer.append((char) (b2 + 48));
                        }
                        b2 = digest[i2] & 15;
                    }
                }
                str2 = stringBuffer.toString();
            }
        } catch (UnsupportedEncodingException unused) {
            str2 = "";
        }
        hashMap.put("X-Auth-Token", str2);
        hashMap.put("X-Locale", Locale.getDefault().getLanguage().toLowerCase(Locale.US) + "-" + Locale.getDefault().getCountry().toUpperCase(Locale.US));
        if (str != null) {
            hashMap.put("X-Device-Token", str);
        }
        StringBuilder c2 = i.d.b.a.a.c("application/json", DummyLocationManager.DELIMITER_RESTORE);
        if (z) {
            c2.append("case=snake");
        } else {
            c2.append("case=camel");
        }
        String a2 = i.d.b.a.a.a(c2, DummyLocationManager.DELIMITER_RESTORE, "time_format=ms");
        hashMap.put(NetworkingModule.CONTENT_TYPE_HEADER_NAME, "application/json");
        hashMap.put("accept", a2);
        return hashMap;
    }
{% endhighlight %}

In this code we can see the X-Date header getting set at line 11. After that the Java class StringBuilder is used to concat a string out of other strings. The resulting concatenated string is hashed with the class messageDigest (at line 23). In the string concatenation process we see MultipartContent.TWO_DASHES being appended to the string two times (lines 13 & 16) and also getting used in the function call to `i.d.b.a.a.a` inbetween (line 14). This function will take the StringBuilder object sb and a number of strings and appends the strings to the sb object. Together this indicates that the value to be hashed starts with two dashes, includes different substrings separated by dashes and ends with two dashes. We also see, that the last substring appended (at line 15) is the same that is assigned to X-Date before (line 11). Putting this together the value to be hashed will look like this:

`--<unknown/str3>--<unknown/str4>--X-Date--`

Based on our former information one of what `X-Auth-Token` consists of, one of the unknown strings has to be `X-App-ID`. By looking at the other code in the same class we can find the assignment of `X-App-ID` and how it is passed first to `this.b` and the into `str3`. The only question left is: What is `str4`? It does not seem to be a HTTP header. I wasn't able to make it out by looking at the source decompilation (I don't have any prior experience with Java/Android Reversing). Because I didn't want to burn to much time on the decompilation, lets turn to a dynamic approach again and use Frida for instrumentation. 

From looking at the decompilation we know that during preparation of the headers a substring is first build with `StringBuilder` and then hashed with SHA1. Alsomost of the content of this string is known. We can use Frida to hook the StringBuilder `toString()` function (our wanted string is used with this in line 17) and log the string to the console. This will fire a ton of false positves but we can use our knowledge about how the string should look like to search through that mass.
Following script will achieve the hooking with Frida (I took this javascript from [here](https://stackoverflow.com/questions/60080096/frida-android-hook-stringbuilder-and-print-data-only-from-a-specific-class)):
{% highlight javascript linenos %}
Java.perform(function() {
  const StringBuilder = Java.use('java.lang.StringBuilder');
  StringBuilder.toString.implementation = function() {

    var res = this.toString();
    var tmp = "";
    if (res !== null) {
      tmp = res.toString().replace("/n", "");
      console.log(tmp);
    }

    return res;
  };

});
{% endhighlight %}
We start the app with following command (needs the Frida setup from the beginning):

`frida -U -f com.runtastic.android -l hook.js --no-paus > strings.txt`

Then we login with our testuser in the app. As soon as we are logged in we can exit the app so that Frida doesn't log any more strings. We then use grep on the created file to find the wanted string:

`cat strings.txt | grep 'com.runtastic.android--'`

This is only one part of our known string but enough to filter down the results to only one or two strings. We can see that the unknown `str4` seems to be the `clientSecret` from the very first login request. So the string to be hashed is:

`--com.runtastic.android--<clientSecret>--<X-Time>--`

We can validate this by building the SHA1 hash out of these components and compare it to a valid request for one of our intercepted requests. It matches.
Now we should have everything to build out a script that does create runs for us!

# Complete the Python script
The completed python script can be found [here in my Github](https://github.com/twenska/reversing_running_app). The code is nothing too special. We have to specify login data of a valid account that has to be created before running the script. Also we have to specify a clientsecret. I think that this value is created on app install and stays static. You can just use some random data or look at what your own app creates. We also put in the distance in metres and the duration of our cheat run. I didn't bother to parse command line options, so you have to edit the values in the code before execution. 
The code is structured in three funtions:

## generateHeaders(clientsecret,token)
This function creates a header with all the necessary (and some unnecessary but nice to have) information. Here we use our knowledge gained through reversing the app to create a valid X-Auth-Token. We shouldn't get any 403 responses. The token needs to be 0 if we didnt't logged in yet. If we have, the token should equal the accessToken from the login response.

## login(clientsecret, username, password)
In here we log in using the specified username and password. These values are used in the variable payload that represents the JSON formatted body of the POST request we saw earlier. The payload has to be gzip encoded before sending it out. (As we saw in the intercepted communication of the app)
If the function is successful it returns the accessToken. Otherwise it returns -1.

## create_run(clientsecret, token, duration, distance)
We copy most of the payload structure the app generated itself during our interception. We will only change the timestamps so that the runs seem recent. We dynamically specify the duration and the distance of our run and set the Authorization header to the accessToken of our login. Then we send all this - gzip encoded - to the API endpoint.

# Conclusion
Pretty fun excersise that I can now use if I don't want to take a run but still want to please my coach. The app uses a pretty basic & flat API that we can easily control with the requests library in Python. We had to get the certificate pinning out of the way, which was easy using Frida + Objection. The only real headache was to figure out the X-Auth-Token to validate our requests. We did that by using a mix of static and dynamic analysis. I had some fun doing this!
The running script looks like that:
<figure>
	<a href="https://raw.githubusercontent.com/twenska/twenska.github.io/master/assets/images/runningApp_working_script.png"><img src="https://raw.githubusercontent.com/twenska/twenska.github.io/master/assets/images/runningApp_working_script.png"></a>
</figure>
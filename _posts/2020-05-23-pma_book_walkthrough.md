---
title: "Analyzing a Malware Loader - Practical Malware Analysis  Walkthrough Lab 14-3"
excerpt_separator: "<!--more-->"
categories:
  - Blog
tags:
  - Reverse Engineering
  - Practical Malware Analysis
  - Books
  - Windows
---
This post shows an approach to analyse the malware provided in the Lab 14-3 of the book [Practical Malware Analysis](https://nostarch.com/malware). I wrote a short review about the book [here](https://blog.twenska.de/blog/pma_book_review/).

# TL;DR
The piece of malware we analyse here is a loader that can be used to drop more malware to an infected endpoint. It also has the functionality to sleep, deactivate itself (though not removing evidence) and change the URL it is getting commands from. In this post I reverse engineer the the malware and create different signatures to detect (parts of) the malware's network traffic, its binary file and its behaviour on the endpoint.

The lab is coming from the chapter *Malware-Focused Network Signatures*, so our target will be to develop (network) signatures for the provided malware. I won't use the provided questions as a base and also haven't done the related lab 14-1 before that. 

The file to analyse is a single EXE. You can obtain it [here](https://practicalmalwareanalysis.com/labs/). I mainly used Cutter for statically reversing the file. But I noticed that it didn't recognize a lot of standard C functions like *strcpy* or *strstr* so I also used IDA to identify these.

# Basic Analysis
We start the analysis with a look at the strings and imports of the binary. We find a few interesting imports, mainly *Create/Read/Write-File*, *CreateProcess*,*LoadLibrary* and imports for remote activity from *wininet.dll* and *urlmon.dll*:
<figure>
	<a href="/assets/images/pma_blog_imports.png"><img src="/assets/images/pma_blog_imports.png"></a>
</figure>
In the strings overview we find more hints to what the malware may do: We have a string that looks like it could be used in base64 encoding/decoding, a User-Agent string, a file path and a URL:
<figure>
	<a href="/assets/images/pma_blog_string_hint_b64.png"><img src="/assets/images/pma_blog_string_hint_b64.png"></a>
</figure>
<figure>
	<a href="/assets/images/pma_blog_strings.png"><img src="/assets/images/pma_blog_strings.png"></a>
</figure>

Next, we will execute the malware in a "safe" lab environment. We will monitor it's behaviour using procmon and Wireshark. We can spoof network requests using FakeNet-NG, so we don't have to let the malware communicate with the the internet.

On execution we can see in procmon that the malware interacts with the file *C:\autobat.exe*. 
<figure>
	<a href="/assets/images/pma_blog_procmon_file_access.png"><img src="/assets/images/pma_blog_procmon_file_access.png"></a>
</figure>
We saw this file path as a string. The malware also makes a request to the URL we identified in the strings: *http://practicalmalwareanalysis.com/start.htm*.
In the HTTP request a weird User-Agent string is used:

{% highlight javascript linenos %}
GET /start.htm HTTP/1.1
Accept: */*
Accept-Language: en-US
UA-CPU: x86
Accept-Encoding: gzip, deflate
User-Agent: User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1;
.NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)
Host: www.practicalmalwareanalysis.com
Cache-Control: no-cache
{% endhighlight %}

The file access and the network request seem to continue to happen every half minute or so. We can't spot the malware doing anything else, so we turn to a more advanced analysis approach.

# Disassembling the Malware
The main function of the malware calls four other functions that are unknown to us just now:
<figure>
	<a href="/assets/images/pma_blog_main_graph.png"><img src="/assets/images/pma_blog_main_graph.png"></a>
</figure>

 There are three comparisons followed by conditional branches, that either skip a block of code (if *var_208h* is zero) or go to the exit of the program (if *var_4h* is zero). If the latter value is not zero, we enter a loop that is interrupted by a 20 second sleep.

Instead of jumping blindly into the middle of the disassembly, lets focus at one of the two behaviours we already saw: The file access or the network request. We will choose the network request here.

Recalling the imports of the malware, the imports from *WININET.dll* and/or *urlmon.dll* could be used to create HTTP requests. The cross references of one of these imports, *InternetOpenURLA*, indicate, that it was only used in the third unknown function called from main (which I renamed *unknown_main_func3* before to recognize it):
<figure>
	<a href="/assets/images/pma_blog_xrefs_InternetOpenURL.png"><img src="/assets/images/pma_blog_xrefs_InternetOpenURL.png"></a>
</figure>
So, lets dive into this function first...

## Network Beacon
Inside the function we see a call to *InternetOpenA* (at 0x00401253)  that takes the User-Agent string we saw in the request and a few headers as arguments, to create a handle to an InternetObject. This handle is passed to *InternetOpenURLA* (at 0x00401279) together with an URL (at 0x00401275) that needs to be provided as an argument in the first hand. If the malware fails to open an URL handle, it will exit the function here. 
<figure>
	<a href="/assets/images/pma_blog_read_data_from_URL_assembly_one.png"><img src="/assets/images/pma_blog_read_data_from_URL_assembly_one.png"></a>
</figure>
Otherwise a call to InternetReadFile (at 0x004012c7) will be issued to get the first 2048 bytes of the remote file and write them to a buffer:
<figure>
	<a href="/assets/images/pma_blog_InternetReadFile_asm.png"><img src="/assets/images/pma_blog_InternetReadFile_asm.png"></a>
</figure>
We will rename the function *read_data_from_URL*.
The buffer is searched for the string *<no*,(at 0x004012e7) which - in this context - could be the beginning of a HTML tag.If the string isn't found, the next bytes are read from the remote file, up until there are no more bytes to read. If *<no* is found, a pointer to its is passed to another unknown function. (at 0x0040130d) The accessed URL and a buffer (specified in main function) are passed as additional arguments. 

<figure>
	<a href="/assets/images/pma_blog_read_data_fromURL_asm_two.png"><img src="/assets/images/pma_blog_read_data_fromURL_asm_two.png"></a>
</figure>

Looking at the graph of the called function, we see a lot of single byte comparisons. If these comparisons don't match, the function returns immediately. We will call the function *check_File*. Following the single byte checks, there are two bigger code blocks that also have paths that could fail the function. The structure of the function is shown here:
<figure>
	<a href="/assets/images/pma_blog_structure_of_checkFile.png"><img src="/assets/images/pma_blog_structure_of_checkFile.png"></a>
</figure>

The single byte comparisons check, that the first 9 bytes of the passed string start with *noscript>*. The bytes are not checked in their right order, to make analysis a little bit more complex. Next, the URL (one of *check_File*s arguments) is copied to a new buffer(*str_URLwoPath*; at 0x004010ac) and is searched backwards for a backslash.(at 0x004010b6) The malware inserts a NULL byte at the location of the backslash.(at 0x004010cb) If the variable *str_URLwoPath* is used after the insertion, it will now terminate just before the path. For example, the URL used earlier, (*http://practicalmalwareanalysis.com/start.htm*) would be truncated to *http://practicalmalwareanalysis.com*.

The truncated URL is searched in the string, starting with *noscript>*.(at 0x004010d9) If found, there will be a pointer set to it's location and then moved to the first byte that comes after *str_URLwoPath*.(at 0x004010fc) From there, the string *96'* is searched (at 0x0040110a)and a NULL byte is inserted at it's beginning.(at 0x00401127) As last action, a *strcpy* copies the content from inbetween the end of the URL (set as pointer) and the inserted NULL byte (at the beginning of the constant string*96'*) to *arg_ResultBuffer(second argument of *check_File*; at 0x00401132)

The line in the remote file has following structure (the URL must be equal to the location of the remote file; its URL):

**\<noscript\>...\<http://practicalmalwareanalysis.com\>\<extracted_content\>96'**
<figure>
	<a href="/assets/images/pma_blog_checkFile_extractCommand.png"><img src="/assets/images/pma_blog_checkFile_extractCommand.png"></a>
</figure>

Going back to the function *read_data_from_URL*, we see that it will continue to look for lines that start with *<no*, extracts its content and will eventually return. The most interesting value will be returned in the buffer *arg_ReturnBuffer* that is passed from the caller of *read_data_from_URL* and has the extracted data from the remote file in it.

The function seems to implement beaconing functionality, in that it's called continually from the main loop and tries to read (hidden/obfuscated) data from a remote URL.

Based on the analysis of *read_data_from_URL* there are two open ends we will have to analyze further:
1. The arguments passed to *read_data_from_URL* include the URL that the extracted content is coming from. We will have to find out how it is generated before the call to *read_data_from_URL* in main.
2. The extracted content will be used in a function after *read_data_from_URL*. We need to find out how it is used, so we can determine what the extracted content is.

Lets continue with finding out where the URL comes from.
 
## Finding the URL
Looking back at the function graph of main, we now identified *unknown_main_func3* to be *read_data_from_URL*. Like we concluded in our analysis of the function, it has two arguments. The URL is the first argument in *read_data_from_URL* and therefore the one that is pushed on the stack last (*var_204h*) The other pushed value is the buffer in that the extracted content is returned. We will rename the variables to *str_URL* and *lp_BufferWRemoteData*.

Tracing back the code in main, we can see that *str_URL* is passed as argument to *unknown_main_func2*. After that we can't see any other modification of it, so it will be set in this function.

The function graph of *unknown_main_func2* shows two main paths inside the function:
<figure>
	<a href="/assets/images/pma_blog_get_URL_from_file_graph.png"><img src="/assets/images/pma_blog_get_URL_from_file_graph.png"></a>
</figure>
Looking at the code before the two paths split, we can conclude that the code flow depends on a call to *CreateFileA*. The malware tries to get a handle on the file *C:\autobat.exe*. If the file exists, the right path is taken - otherwise the code flows left.

On the right path a call to *ReadFile* is made and the contents of the file are written to *str_URL* (first argument of the function). The file *C:\autobat.exe*, that we already spotted earlier with procmon, will not contain binary data, but most likely the URL that the malware communicates with. 

The left code path shows how the file is created, when it doesn't exist. An additional function is called with the static string *http://practicalmalwareanalysis.com/start.htm* provided as an argument. Inside the function the file *C:\autobat.exe* is created and the string passed to the function is written to it. After creating the file we return to *unknown_main_func2* and call itself again (a recursive call) to read the newly created file.

All in all, *unknown_main_func2* is looking for the file *C:\autobat.exe* and reads out the content of it, which will be the URL used by *read_data_fromURL*. If the file doesn't exist, it will be created with the default value *http://practicalmalwareanalysis.com/start.htm*. We will rename the function *get_URL_from_File*.

## Execute commands
As next step we will try to find out what happens with the data extracted in *read_data_from_URL*. The extracted content is in the variable *lp_BufferWRemoteData* after the call to *read_data_From_URL* inside main. It is passed to *unknown_main_func4*, together with the variable *var_208h*.

*unknown_main_func4's* dominating structure is a jump table (represents a switch-statement in C):
<figure>
	<a href="/assets/images/pma_blog_jump_table_graph.png"><img src="/assets/images/pma_blog_jump_table_graph.png"></a>
</figure>
Before the jump table code begins, the data from *arg_lp_bufferWRemoteData* is prepared. With two calls to *strtok* (tokenize_string; first at 0x004016a3, second at 0x004016b4) the data is splitted at two backslashes. The first byte (=char) from behind the first backslash is moved to the variable *command* (at 0x004016c2) and substracted by 0x64 which equals *d* in ASCII (at 0x004016cb). If the result is bigger than 15, a jump is made. that will take us to the default case of the switch-statement (at 0x004016d1). The default case exits the function without doing anything.  With this information we can already conclude, that this single byte of the extracted content should be a char between 0x64 - 0x72 (or d - r). 
The second call to *strtok* will get the location of the second token (backslash) in *arg_lp_bufferWRemoteData*.
<figure>
	<a href="/assets/images/pma_blog_execute_commads_jt_prep.png"><img src="/assets/images/pma_blog_execute_commads_jt_prep.png"></a>
</figure>
The jump table has five cases. The jump at 0x004016e2 is used to execute one of these. The fifth case is the default one that will just exit the whole function, we don't know what the other four cases are doing. 

To decide which case to jump to, *command* is used as an index into a structure (at 0x004016dc) that holds different offsets. The structure is 15 bytes big and contains 5 different byte values that represent the 5 cases of the jump table. The first byte equals 00, the 10th byte equals 01, the 14th byte equals 02, the 15th byte equals 03 and all the other equal 04.
<figure>
	<a href="/assets/images/pma_blog_offset_for_jump_table.png"><img src="/assets/images/pma_blog_offset_for_jump_table.png"></a>
</figure>
The value 04 will result in jumping to the default case and exiting the function. We will reach the other cases with indices 0, 10, 14 or 15. Reverting the substraction of 0x64 we get the chars *d, n, r, s* that will trigger the different cases. These different chars seem to resemble commands (therefore the name of the variable), that control the behaviour of the malware. We will call this function *execute_commands*.

Following we will analyze the different cases:
<figure>
	<a href="/assets/images/pma_blog_execute_command_commands.png"><img src="/assets/images/pma_blog_execute_command_commands.png"></a>
</figure>

### Case 0/d - Loader
If the *command* equals a *d*, a new function is called with the data obtained by the second call to *strtok* as an argument. The new function first calls just another function (at 0x00401579) and passes through its arguments. After that function call, it attempts to download a file with *URLDownloadToCacheFileA* and executes the downloaded file as a new process. We will rename the function to *loader*, as this command enables an attacker to load additional malware to the infected host. The letter *d* that is used as command could stand for *download*.
<figure>
	<a href="/assets/images/pma_blog_loader_functionality.png"><img src="/assets/images/pma_blog_loader_functionality.png"></a>
</figure>
The function called at the beginning of *loader* (at 0x00401579) seems to do decoding on the second part of *arg_lp_bufferWRemoteData*. The decoding function loops over the whole length of the provided data, takes two bytes of it, converts them to integer values and uses them as an index into a structure that includes all lower-cased characters, numbers 0-9 and the special cases */ . :*. At the very beginning of our analysis we took this structure as a hint for base64 encoding, but it is not. The second part of *arg_lp_bufferWRemoteData* consists of two digit numbers (as strings, thats why they will be converted) between 00 - 38 (range of the structure). These will be mapped to one of the characters in the structure. The result will be returned in a buffer, that was specified as argument. 
<figure>
	<a href="/assets/images/pma_blog_decoding_of_URL.png"><img src="/assets/images/pma_blog_decoding_of_URL.png"></a>
</figure>
Looking back at the *loader* function we will see that this decoded buffer is used as the URL from that additional code is downloaded. The malware hides this URL in its beaconing by encoding it. This knowledge will be important to create network signatures later on.

### Case 1/n - Stop Malware
The only thing done in this case, is setting the variable *var_4h* to one. This variable will be used as a return value of the whole function *execute_command*. In any other case its return value would be zero. In the main function this return value is compared to zero after the call to sleep (main at 0x004017e7). Returning one from *execute_command* causes the following jump to fail and ends the loop of main, effectively ending the running malware.

### Case 2/r - Change Beacon URL
Like with the *d* command, the *r* command passes the *encoded_URL* to a function it calls. It will use the same decoding routine and then use the decoded URL to call the function to create the *C:\autobat.exe* file we found in *Finding the URL*. We will call this function *change_C2_URL* (in retrospective changing C2 with Beacon would have been more consistent, so please handle it as synonyms here). After the file is created, the second argument of the *execute_command* function will be used, to set the variable *var_208h* in main to one. This will force the malware to refresh the beaconing URL by rereading the autobat.exe file.

### Case3/s - Sleep
This command will trigger the malware to sleep. The duration can be specified the same way the encoded URL was passed, but the value is not decoded. If no value is specified, the malware will sleep for 20 seconds.

# Summarizing Analysis
The malwares main functionality is that of a loader. An attacker can use it as a first stage payload that, when executed, can deliver more malicious code to the victim. In a real world scenario the attacker could use the loader to establish persistence on the infected host, do reconaissance on the host and it's network, move laterally in the local network and manipulate the machines in a lot of ways.

By writing the Beacon URL to a local file and providing a command to change it, the attacker can regularly change the URLs, to evade detection by this IoC. Beacuse the beaconing is done over the standard http protocol, the commands are hidden in a HTML tag and the commands are not suspicious (single char and an encoded URL), the beaconing of the malware can be easily mistaken for legit web traffic. These techniques are implemented to evade detection and make analysis more complex.

# Signatures
In the book this malware comes from, only a Snort signature is created. In todays world, however, YARA is as popular as Snort. Sigma gets more and more usage, too. By combining all three, we can create  generic signatures for network traffic, files and logs and our detection capabilities get alot better.

The signatures I show will mostly contain Network and Host Artifacts we found while reverse engineering. I will not use signatures for Domain Names, URLs or Hashes, as they are really easy to evade and don't need extensive analysis. If you want to know more about how to use knowledge of malware to detect it effectively, you should take a look at the [Pyramid of Pain](http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html). The artifacts we use here match into the pyramids category to be 'annoying' to the attacker, and that is exactly what a defender wants to be!

The signatures I write here are just quick PoCs. They are missing testing and metadata. We could also write more signatures for different parts of the malware. But they will provide an insight into what a signature is and how it is created from our analysis.

## Network Signature - Snort
In the network section we will have to focus on the requests of the beaconing the malware implements. The network traffic to download additional malicious code is using only the standard http protocol, so we won't be able to differentiate this from legit traffic. The beaconing, however, has things that stand out: The used User-Agent string is malformed (it includes *User-Agent:* twice) and we reversed the protocol the malware uses to get its remote commands.

### Uncommon headers

We use the standard Snort variables *$Home_NET*, *$EXTERNAL_NET* and *$HTTP_PORTS* to specify the flow that our rule should trigger on. In the content we copy the User-Agent string seen in the malware (at the very beginning of the analysis) and switch the colons and spaces to hex values (3a and 20). Following rule should detect the malformed User-Agent header thats hardcoded in the malware:

{% highlight javascript linenos %}
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Malformed User-Agent header"; content:"User-Agent|3a20|User-Agent|3a20|Mozilla/4.0|20|(compatible\;|20|MSIE|20|7.0\;|20|Windows|20|NT|20|5.1\;|20|.NET|20|CLR|20|3.0.4506.2152\;|20|.NET|20|CLR|20|3.5.30729)"; http_header;sid:1000001; rev:1;)
{% endhighlight %}

The malware author will be able to change the code without breaking functionality and provide a normal User-Agent, rendering this signature useless for the new versions of the malware. But it will still be able to detect the recent one.

### Beacons
In the *Network Beacon* part of the analysis we already made outthe basic structure of the remote data the malware is reading:

**\<noscript\>...\<URL\>/\<command\>.../\<encoded_url\>96'**

We also know the first few characters of the *encoded_url* and *URL*, as it needs to start with http:// (in clear and encoded). Theoretically an URL can start with a different protocol, like FTP, but this would break other parts of the malware. If the attacker uses HTTPS for its beaconing, we could not easily inspect the payload with the snort signature. So I won't handle this case here. 

For the *encoded_url* we need to look at where the single letters are located in the structure of the decoding algorithm. For example the backslash is the first character in the structure, so it will be at index 00. The *h* is at index 08 and the *.* is at index 28. Doing this, we get the strings 08202016370000 for http:// and 0820201619370000 for https://.

The command can be one of the four chars *d, n, r, s*. Putting all of this into the structure of the remote file we get:

**\<noscript\>...http://\<Domain\>/\<[d \| r \| s \| n]\>.../[08202016370000 \| 0820201619370000]\<encoded_url\>96'**

We will write two different beacon signatures. One that triggers on just the static parts of the beacon traffic and one where an encoded URL is given (commands d and r).

The first case with only the static parts:

{% highlight javascript linenos %}
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"Lab14.3 - Static Beacon Contents"; content:"<noscript>"; content:"http\://"; distance:0; within:1024; content:"96'"; distance:0; within:1024; sid:1000002; rev:1;)
{% endhighlight %}

The *within:* specifier is used to decrease the load when searching big palyoads that may contain *noscript>* but are legit HTML. This way only the next 1024 bytes will be searched for the rest of the contents.

The second case with encoded URL:
{% highlight javascript linenos %}
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"Lab14.3 - Loader or change C2 URL commands I"; content:"<noscript>"; content:"http\://"; distance:0; within:1024; content:"/08202016370000"; distance:0; within:1024; content:"96'"; distance:0; within:1024; pcre:"/\/[dr][^\/]*\/08202016370000/"; sid:1000003; rev:1;)
{% endhighlight %}

{% highlight javascript linenos %}
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"Lab14.3 - Loader or change C2 URL commands II"; content:"<noscript>"; content:"http\://";distance:0; within:1024; content:"/0820201619370000"; distance:0; within:1024; content:"96'"; distance:0; within:1024; pcre:"/\/[dr][^\/]*\/0820201619370000/"; sid:1000004; rev:1;)
{% endhighlight %}

Here we also use regex, to specify the pattern */command/encoded_url*.
## File Signature - YARA
To create a basic YARA rule, we need to find patterns in the malware that are unique to it and difficult to change for the author (breaking other code). For this signature PoC I chose two structures: The structure that is used to match the command chars with the jump table cases and the one used to decode the URL provided by the beaconing.

Both *should* not be common in other binaries and are not easy to change in the source code, as they would require changing the decoding functionality and/or the structure off the commands. These changes would break functionality between malware versions.

The rule looks like this:

{% highlight javascript linenos %}
rule DetectSructuresLab14_3
{
    strings:
       $jump_table_offsets = { 00 04 04 04 04 04 04 04 04 04 01 04 04 04 02 03 }
       $encoding_structure = "/abcdefghijklmnopqrstuvwxyz0123456789:."
    condition:
       $jump_table_offsets or $encoding_structure
}
{% endhighlight %}

## Log Signature - Sigma
An easy way to detect the malwares presence on a host is checking on the creation of the *C:\autobat.exe* file. The name and location of this file are very uncommon, so it should only trigger on the malware. To detect it, we look for Event ID 11 in the Sysmon Logs of the endpoint and the TargetFileName of *C:\autobat.exe*.

{% highlight javascript linenos %}
title: Create autobat.exe
id: <uid>
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename: 'C:\\autobat.exe'
    condition: selection
status: experimental
{% endhighlight %}

If the malware author chooses a place that is more common for a exe-file and/or makes the name of the file random, detection would be much harder. We could change this to a more general rule to detect any file created in C:\ and ending with .exe, as this is uncommon behaviour in itself. We could also try to write a rule that matches on a file that has .exe as ending, but is either really small or is missing the MZ header.

Another Sigma rule can be written for the loader functionality (Command d). It starts a new process (EventID 1) from a file downloaded to the temporary Internet files. This signature *could* yield a lot of false positives from users downloading and starting executables. The rule would look like this:
{% highlight javascript linenos %}
title: Detect process launch from Temporary Internet Files
id: <uid>
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image: 
            - '*\Downloads\\*'
            - '*\Temporary Internet Files\Content.Outlook\\*'
            - '*\Local Settings\Temporary Internet Files\\*'
    condition: selection
status: experimental
{% endhighlight %}


# Conclusion

With the provided signatures the malware can be identified with different detection methods (e.g. IDS, Endpoint Scanner, SIEM). By creating these signatures, we enable defenders to implement strong detection techniques for the analyzed malware, which can be one main target of reverse engineering malware.

I hope I could give a basic overview of how to conduct the reversing and how to use this knowledge to create signatures. In a real world scenario we would also have to look at initial infection vectors and most important, what additional malware is executed. We could also map the Malware against [MITRE ATT&CK](https://attack.mitre.org), to check if our detection rules would help against this specific malware.

I also think that this walkthrough shows that the Labs from the Practical Malware Analysis book are really awesome and definitely worthwile! The lab shows a lot of the topics the book teaches - from basic Reverse Engineering techniques, to different malware specific techniques.

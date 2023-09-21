<h1>JWipe - Threat Intelligence</h1>

<h2>Description</h2>
In this lab, participants will gain hands-on experience with the Malware Information Sharing Platform & Threat Sharing (MISP). MISP is an open-source threat intelligence platform designed to facilitate the collection, sharing, and analysis of cybersecurity threat information among organizations and communities.
<br />


<h2>Languages and Utilities Used</h2>

- <b>MISP</b> 

<h2>Environments Used </h2>

- <b>Windows 10</b> 

<h2>walk-through:</h2>

Searching MISP events are found when searching for 'ransomware'?

By default, after logging in, we'll be taken to the Events page. Using the search bar on the right-hand side, we can type in ‘Ransomware’ and press the Enter key.

 ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/23abfa6c-f081-48fa-a13d-b533777ed40c)

 
At the bottom of this page we can see the total count of Events that match this search filter, giving us the answer to this question.
 
 ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/d1b6735b-05cf-4e36-9a85-bb30de3b69bc)
 
 
 
 
 
Search for Lockbit and look at the most recent intelligence report. 


Look for indicators, and submit the name of the domain observed in this event
Using the search box we will type in ‘Lockbit’ and then click on the ‘Date’ heading to sort by most recent events first. To view this event we can either click the ID value in the 3rd column, or the eye icon in the final column.
 
  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/ce95ae91-741e-4a12-af33-d6a7cc190fd9)

 
When inside the event, scrolling down we can find the Attributes section, which is used to hold indicators and other useful information.
 
   ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/d3095190-f23d-4b70-894b-2f31983b6d3d)
 
We can either use the search bar above the table, or scroll down until we see the domain property.
 

  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/39d05d8a-92bf-42cd-bac9-134bc2f256d1)

 
 
 
Find the provided YARA rule and discover what the name of the created ransom note file is

Going back to the Event List we'll search for ‘Babuk’ and find there is only one associated Event. Opening this up we'll find a reference to YARA in the Attributes section. In the preview we can't see anything referencing a ransom note, so we'll click on ‘Show all’.
 
  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/192aa52c-b312-446e-a34e-e1d01d913465)

 
Now we can see the full YARA rule file, and see that it is looking for a string related to a created ransom note file.
 
  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/d54dced8-fb12-4c75-81ca-aad8aaf71f27)

 
 
 
 
What high-level Tactics (Initial Access, Collection, etc) contain highlighted techniques?
Searching for 986 will not show the Event, because we need to change our search type to ID:
 
  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/8385af5a-d6a1-4347-92b7-b15e86616e1a)

 
By default in our MISP setup we are not showing the ATT&CK Matrix section, so we need to click this button to show this table.
 
  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/03787403-06b5-427a-8cb9-2c49d5e7d84d)

 
Now that we can see this table, we just need to scroll around and find which Tactic columns contain highlighted Techniques.
 
  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/87de4c60-af04-45e8-8fc1-9a0820560471)

 
Alternatively, we can make things a lot easier for ourselves, and toggle the ‘Show all’ filter in the top-right corner of the table, to hide any techniques that haven't been highlighted.
 
 
 ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/5e27e650-1a0d-491d-b9ee-d63b586a8e6f)
 
 
 
 
How many events have Turla Group as a tag?
We can find the Tags section at the top of the Event. The very first tag is threat-actor="Turla Group", so we'll click this to perform a search for this tag across all of our important intelligence Events.
 
  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/7d327896-2f81-4983-89b0-63c20d062206)

 
Scrolling to the bottom of the Events List page, we can see there are 16 Events that have that specific tag applied.
 
 
 
 
Of the 2 events found, open the oldest one. What is the name of the decoy document used by Turla in this phishing campaign?

We should still have the filter applied for threat-actor="Turla Group". Scrolling down the list of Events, we can find some that have the tag mitre-intrusion-set=turla. Click on this tag to add it to our search filter. We are now left with two Events, so we'll open the one with the older date.
 
  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/e187c9fb-3c29-4299-b33a-3d04adb8dabd)

 
Scrolling down to the Attributes section we need to look at the Type and Comment columns (4 and 9) to search for the decoy document used for phishing their targets.
 
  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/ca6489d6-6b2c-4a8d-9979-883bf92dacaa)

 
 
 
 
How many IP addresses are provided in the event?

Searching for ‘DDoS Booter’ doesn't provide any results, so let's make our search simpler and go for ‘DDoS’. Looking through the Events found, we can find one that mentions Booters.

  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/a8680950-9ef8-44f5-bae3-a592216f7580)

 
 
Looking at the Attributes table we can see that there are some IP addresses using the ip-dst Type value, so let's search for ip-dst in the Attributes search box. Scrolling to the bottom we can see the number of indicators that are IP addresses!
 
  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/41fd79b9-de60-4098-a90c-18be6c594fc8)

 
 
 
 
What is the original filename? (Copy the link out of the lab, as it has no internet - as the URL is long, you will need to copy it in two parts to ensure you have the full address)

Search for CoalaBot on the List Events page and open the single event. Scrolling down we can find references to a malicious file, and a link to a VirusTotal report page.
 
  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/0de262c0-d42f-4d14-9465-34ead198b397)

 
We now need to copy the hyperlink (right-click > copy) so that it appears in the lab Clipboard. PLEASE NOTE due to the character limitation, you will not copy the entire URL in one go, so VirusTotal would tell you the page can't be found. You'll need to copy the last bit of the URL from the lab again to ensure you have the full page (we're sorry - we'll try get this limitation increased shortly).
 
 ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/423a589c-6479-480d-8da5-5303f3c43aba)
 
 
Visiting the VirusTotal page, we need to go to the Details tab, and scroll down slightly to see the Signature Info section, which gives us the original filename of cla.exe.
 
 
 
 
Read the report, as we need to find a way to identify if any of our systems are compromised. Find an IP address that systems will communicate to as soon as they are infected.

We'll search for ‘Rhombus’ on the List Events page and open the Event. Scrolling down to the Attributes table we can find a link to the threat report, posted on Reddit.

 ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/534ff60a-de5d-4b35-b1c6-be53d0339e5b)

 
We can copy this link to the lab Clipboard in one go, then enter it into a browser on our host computer. This takes us to a post in the subreddit ‘r/LinuxMalware’. 


  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/6245f36d-171d-45a2-8adf-9bdcc9d606b2)

 
 
Now it's time to read the report to understand how this malware works. Eventually we come to a section that mentions the initial command-and-control callback to inform the attacker's server that a device has been infected and the malware has successfully run:
 
 ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/6f3dd573-6ff2-4553-a50e-f5b1ce7b2b32)
 
 
This gives us the IP address and port (2020) that is used, allowing us to check our environment for logs where the destination IP is 209.126.69.167 and the destination port is 2020!
 
 
 
 
Find the CVE that is being exploited within MiVoice. 

There are multiple ways to find the answer for this question, however we'll show you our thinking behind a single method.

First we'll search for ‘MiVoice’ on the List Events page and open the associated Event. Taking some time to read the items in the Attributes table, we start to see multiple references to one CVE (Common Vulnerabilities and Exposures, an identification system for vulnerabilities) in multiple rows.
  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/44891569-4e93-4519-9b2f-defe267e2c1e)
 
Now that we have the CVE, let's search on Google to find the National Vulnerability Database page for it.
 
  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/7609e82d-af59-4ad4-8047-d8ef018821fe)

 
On the NVD page we can find a section that includes a link to the Vendor Advisory. This is a webpage that has been posted by the company Mitel, which created MiVoice, so it will contain the most accurate information about the vulnerability.
 
  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/daf7f632-7f40-4b6d-adc9-807cf96b076d)

 
And here we have it! The affected versions of MiVoice! Based on the answer format, we need to submit ‘19.2 SP3 and earlier’.
 
  ![image](https://github.com/abdullaah019/Threat-Intelligence/assets/139023222/6f048c80-80a7-4e85-af20-ee12ba9b8430)

 


<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>

---
title: "Book review: The Hacker And The State"
excerpt_separator: "<!--more-->"
categories:
  - Blog
tags:
  - Misc
  - Books
  - Review
---
# TL;DR
In [The Hacker And The State](https://www.amazon.com/Hacker-State-Attacks-Normal-Geopolitics/dp/0674987551) author Ben Buchanan gives the reader an overview about the influence of cyber operations on the worlds politics. To do this, the author looks at past operations and their consequences. The book does a good job in showing possibilities and limits of cyber operations and leaves the reader with a more informed opinion about his topic. The book is interesting for anyone interested in geopolitics and/or cybersecurity and doesn't require any technical knowledge.

# Structure of the book
The book is structured in the three parts *espionage, attack and destabilization*. For each of these parts the author selected 4-5 past cyber operations and analyses them. His focus lies on describing the operation, showing its consequences and forming an opionion about the success of the operations from the eyes of the adversary. As a lot of these operations are confidential ( e.g. to nations intelligence services), the author has to rely on sources like journalists work, open communications or leaks. The sources used are provided in the text.
As the information from these sources is limited, the author often has to formulate an opinion and can't cite facts. (This is NOT a bad thing, but should be kept in mind while reading the book)

One of the main topics of the book is the distinction of operations between *shaping* and *signaling*, two terms used in statescraft. *Shaping* is meant to "change the game" by directly interfering with an adversary, while *Signaling* is meant to "hint credibly" at power and consequences to influence an adversary.

I want to highlight three of the operations analysed in the book:


### BYZANTINE CANDOR (Chapter 5)
[Byzantine Candor](https://en.wikipedia.org/wiki/PLA_Unit_61398) is a Chinese threat actor tied to the Peoples Liberation Army (PLA). The groups target was to spy on the US Department of Defense and different companies mostly located in the US. As the NSA spotted several intrusions from chinese threat actors, they decided to meet them with active counterintelligence measures - or to *hack the hackers*. The *Targeted Access Operations (TAO)* unit from the NSA successfully attacked several jump hosts used by the adversary. They also breached the ISP responsible for connecting *Byzantine Candor* to the internet. With the combined information the NSA could connect the threat actor to the chinese PLA and actively monitor ongoing and past operations of them. The NSA gained intelligence useful for defending against future threats and knowledge about the targets of a foreign adversary.
 
The whole chapter shows that counterintelligence is all about information. As information today is stored on computers, cyber operations are heavily used in counterintelligence efforts.

### The Shadow Brokers (Chapter 11)
[The Shadow Brokers](https://en.wikipedia.org/wiki/The_Shadow_Brokers) leak is most likely the biggest (technical) information leak from a nations intelligence service. Beginning in 2016, the group continually released tools and documentation used by the *Equation Group* (which is tied to the NSA). Included were several critical zero days, e.g. [CVE-2017-0144](https://nvd.nist.gov/vuln/detail/CVE-2017-0144). The leaks were splitted over several messages and the groups self-claimed intent was to make money of the leaks. There were a lot of consequencces from the leak, as criminals used the information for malware campaigns (e.g. WannaCry or NotPetya) against US targets. As the NSAs job is to secure information systems in the US, they got criticised for keeping vulnerabilities secret and for losing them.

It is still unknown how the information leaked or who was respondible for it. The *Hacker and the State* explains the whole incident and all related activities. I think I gonna dive deeper into the whole Shadow Brokers story later, as reading about it made me intrigued about more details.

### NotPetya (Chapter 13)
[NotPetya](https://www.theregister.com/2017/06/28/petya_notpetya_ransomware/) was a ransomware attack on companies operating in Ukraine. It is tied to Russian intelligence services. The malware spread through a tax software popular in Ukraine. The russian hackers breached the company behind that tax software and used their official update channels to infect users of the software. This hit alot of small Ukraine companies, but also some big names like  Merck, FedEx and Maersk.

The malicious code used various automated techniques to move laterally in the infected networks and deployed ransomware to every machine it could reach. n this lateral movement they used several vulnerabilities from the Shadow Brokers leaks. The ransomware deployed had no way to decrypt files and therefore was merely meant to destroy data.

The shipping company Maerck lostnearly all of its computers and servers o the attack and could only rebuild them, because a backup of their Active Directory was availaible from a small Location in Ghana, that was offline during the outbreak. The pharmaceutical company Merck declared a loss of 679$ million dollars because of NotPetya.

# Conclusion
The three operations I described here should let you see whats in this book. If you think these short excerpts sound interesting, the book won't disappoint you. 

The whole book shows the importance of cyber operations in geopolitics. Whether the target is to spy, to counter intelligence, to make money or to disrupt an adversary, hacking can be the right tool. Even more so as hacking is not limited to the *big* players USA. Russia and China. Even small countries like North Korea or Iran and even criminal groups can shape the actions of the world by attacking information systems. Still, cyber operations are not always the right tool. They often have to be done in secret and are therefore not easy to use to signal your adversary, but rather to shape the situation you are in. The big fears of a open cyber war with attacks on Industrial Control Systems and blackouts is not realistic going forwards.

I hope I could give you an insight into the book. I really liked it and therefore recommend it if you like the combination of cybersecurity and geopolitics. On eof th slight negative points is the US focus of the book. I would have liked to read more about other nations, for example Israel or Germany. Next up on my (non-technical) reading list will be [Active Measures](https://www.amazon.com/Active-Measures-History-Disinformation-Political/dp/0374287260)

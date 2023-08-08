# Hydra

Hydra bir brute force aracıdır. Kullanıcı adı ve parola listeleri kullanarak bir web sitesine brute force atmak için kullanılabilir.

## Kullanımı

### Hydra ile bir web sitesine brute force atmak için

```sh
hydra -l kullanici_adi_listesi.txt -P parola_listesi.txt <hedef_ip_adresi> <hedef_protokol>
```

- -l: Kullanıcı adı listesi dosyasını belirtir.
- -P: Parola listesi dosyasını belirtir.
- hedef_ip_adresi: Saldırının yapılacağı hedefin IP adresi.
- hedef_protokol: Hedef protokolü belirtir (örn. ssh, ftp, http).

<a href="https://www.kali.org/tools/hydra/" target="_blank">Hydra</a>

<hr>

# Nmap

Nmap, ağ keşfi ve güvenlik denetimi için kullanılan bir araçtır. Ağdaki bilgisayarları ve servisleri taramak için kullanılabilir.

Temel Taramalar:

TCP SYN Taraması: nmap -sS <hedef_IP>
TCP Bağlantı Taraması: nmap -sT <hedef_IP>
UDP Taraması: nmap -sU <hedef_IP>
ICMP Ping Taraması: nmap -sn <hedef_IP>
Belirli Portları Tarama:

Tek Bir Port: nmap -p <port_numarası> <hedef_IP>
Birden Fazla Port: nmap -p <port_numaraları> <hedef_IP>
Belirli Bir Aralık: nmap -p <başlangıç_port>-<bitiş_port> <hedef_IP>
Hız ve Performans Ayarları:

Tarama Hızını Ayarlamak: nmap -T<0-5> <hedef_IP>
Tarama Performansını Artırmak:

```bash
nmap --min-parallelism <sayı> --min-rtt-timeout <milisaniye> <hedef_IP>
```

## Ağ Tarama:

### Belirli Bir Ağda Tarama:

```bash
nmap <ağ_adresi>/<subnet>
```

### İşletim Sistemi Tespiti:

```bash
nmap -O <hedef_IP>
```

## Servis ve Versiyon Tespiti:

### Servis Tespiti:

```bash
nmap -sV <hedef_IP>
```

Tarama Sonuçlarını Sadece Servis ve Versiyonlarla Sınırlamak:

```bash
nmap --open -sV <hedef_IP>
```

### Script Taraması:

```bash
nmap -sC <hedef_IP>
```

Belirli Bir Script'i Kullanarak Tarama:

```bash
nmap --script <script_adı> <hedef_IP>
```

## Gelişmiş Taramalar:

### Tüm Portları Tarama:

```bash
nmap -p- <hedef_IP>
```

### Belirli Bir Script Dizini Tarama:

```bash
nmap -p <port_numarası> --script <dizin_adı> <hedef_IP>
```

### Ağ Topolojisi Tespiti:

Traceroute Taraması:

```bash
nmap --traceroute <hedef_IP>
```

### Belirli Bir TTL Değeriyle Traceroute Taraması:

```bash
nmap --traceroute --ttl <TTL_değeri> <hedef_IP>
```

Hedef Sistemdeki Hostları Tespiti:

Hedefteki Hostları Tespiti:

```bash
nmap -sn <hedef_IP>
```

### Belirli Bir Ağda Yaşayan Hostları Tespiti:

```bash
nmap -sn <ağ_adresi>/<subnet>
```

Not: Nmap, birçok seçeneği ve tarama yöntemini destekleyen oldukça kapsamlı bir araçtır. Yukarıdaki "cheatsheet" sadece temel kullanımı kapsar. Nmap hakkında daha fazla bilgi için man nmap komutunu kullanabilir veya Nmap belgelerini inceleyebilirsiniz. Ayrıca, Nmap'daki tüm seçenekleri ve tarama yöntemlerini görmek için nmap --help komutunu kullanabilirsiniz.

<a href="https://nmap.org/" target="_blank">nmap</a>

<hr>

# WireShark

Wireshark, ağ trafiğini yakalamak, izlemek ve analiz etmek için kullanılan açık kaynaklı bir ağ protokol analiz aracıdır. Ağda iletilen veri paketlerini anlamak, hataları teşhis etmek, ağ performansını değerlendirmek ve güvenlik sorunlarını tespit etmek için kullanılır. Wireshark, grafik arayüze sahip olması nedeniyle hem deneyimli ağ uzmanları hem de yeni başlayanlar tarafından kolaylıkla kullanılabilir.

Wireshark, çeşitli ağ protokollerini destekler ve paketleri filtrelemek ve analiz etmek için geniş bir özellik yelpazesi sunar. Aşağıdaki gibi temel özellikleri bulunur:

- Paket Yakalama: Wireshark, ağ arayüzlerinden gelen veri paketlerini yakalayabilir. Bu paketler, yerel ağınızda geçen trafiği veya belirli bir hedef IP adresine yönlendirilen trafiği içerebilir.

- Protokol Analizi: Wireshark, farklı ağ protokollerini anlar ve paketleri ilgili protokollerin yapılarına göre çözümler. TCP, UDP, ICMP, HTTP, DNS, FTP, SMTP gibi yaygın ağ protokollerini anlayabilir.

- Paket Filtreleme: Wireshark, filtreler kullanarak belirli türdeki paketleri görüntülemeye olanak tanır. Bu, trafiği belirli protokoller, kaynak veya hedef IP adresleri veya belirli zaman aralıklarıyla sınırlandırmak için kullanılabilir.

- İstatistikler ve Performans Değerlendirmesi: Wireshark, paket trafiği istatistikleri sunar ve ağ performansını değerlendirmek için paket zamanlamalarını, gecikme sürelerini ve diğer metrikleri izleyebilir.

- Renk Kodlama: Wireshark, farklı paket türlerini ve durumlarını renk kodlama ile gösterir, bu da analiz yapmayı kolaylaştırır.

- Flows Analizi: Wireshark, aynı kaynaktan gelen veri akışlarını gruplandırabilir ve bağlantıları analiz edebilir.

- Ses ve Video Analizi: Wireshark, ses ve video akışlarını izlemeye ve sorunları teşhis etmeye yardımcı olabilir.

Wireshark, ağ yöneticileri, güvenlik uzmanları, ağ güvenliği araştırmacıları, uygulama geliştiricileri ve birçok farklı alandaki profesyoneller tarafından kullanılır. Ayrıca, eğitim amaçları için de yaygın olarak kullanılan bir araçtır.

<a href="https://www.wireshark.org/" target="_blank">Hydra</a>

<hr>

# MetaSploit Framework

Metasploit Framework, güvenlik testleri ve penetrasyon testleri için kullanılan popüler bir açık kaynaklı güvenlik çerçevesidir. Penetrasyon testleri, mevcut güvenlik açıklarını ve zayıf noktaları tespit etmek için ağ ve sistemler üzerinde kontrollü saldırılar gerçekleştirme sürecidir. Metasploit Framework, bu tür testler için kullanılan bir dizi aracı bir araya getirerek saldırganların yetkilendirilmemiş erişime sahip olabileceği zayıf noktaları tespit etmek ve gidermek için kullanılır.

Metasploit Framework, bilgisayar korsanları ve kötü niyetli kişiler tarafından kötüye kullanılabilecek saldırıları otomatikleştirmek için kullanılabilecek güçlü bir araçtır. Bu nedenle, yalnızca etik hackerlar, güvenlik uzmanları ve sistem yöneticileri tarafından yasal ve etik güvenlik testleri için kullanılması önerilir.

## Metasploit Framework, bir dizi güçlü aracı içerir:

### Exploitler:

Metasploit, güvenlik açıklarını sömürmek için kullanılan exploitler içerir. Bu exploitler, hedef sistemlerdeki güvenlik açıklarını tespit etmek ve kötü amaçlı kod yürütmek için kullanılabilir.

### Payloadlar:

Payloadlar, hedef sistemde çalıştırılmak üzere tasarlanmış kötü amaçlı kod parçalarıdır. Exploitlerin hedef sistemde başarılı olması durumunda, payloadlar hedefe yönelik istenilen işlemi gerçekleştirebilir.

### Aux Modülleri:

Metasploit Framework, keşif, bilgi toplama ve diğer farklı görevler için yardımcı modüller içerir.

### Encoderlar:

Encoderlar, payloadların algılanmasını önlemek için kötü amaçlı kodları şifrelemek ve deşifre etmek için kullanılır.

Metasploit Framework, komut satırı arayüzü (msfconsole) ve grafiksel kullanıcı arayüzü (Armitage) olmak üzere iki temel arayüze sahiptir. Msfconsole, Metasploit Framework'ün esas çalışma ortamıdır ve kuvvetli bir komut satırı arayüzü sunar. Armitage ise daha kullanıcı dostu bir grafiksel arayüze sahiptir ve kullanıcıların saldırıları görselleştirerek yönetmelerine olanak tanır.

Metasploit Framework, düzenli olarak güncellenir ve sürekli olarak yeni güvenlik açıkları ve exploitler eklenir. Bu nedenle, güncellemeleri takip etmek ve mevcut saldırı vektörlerine karşı korumak önemlidir. Aynı zamanda, yalnızca yasal ve etik sınırlar içinde kullanılması gerektiğini unutmamanız önemlidir.

## Metasploit Framework'ün Kullanım Alanları

- Güvenlik Açıklarının Tespiti: Bir şirketin ağını veya sistemini test etmek için kullanılabilir. Metasploit, potansiyel güvenlik açıklarını tespit etmek için çeşitli exploitler ve zayıf noktaları içeren modüller sağlar.

- Şifre Güvenliği Değerlendirmesi: Metasploit, kullanıcı hesaplarının güvenliğini test etmek için parola kırma ve güçlü parola politikalarını deneme gibi işlemleri gerçekleştirebilir.

- Sosyal Mühendislik Saldırıları: Metasploit, sosyal mühendislik saldırılarını simüle ederek kullanıcıların davranışlarını ve tepkilerini değerlendirmeye yardımcı olabilir. Örneğin, phishing e-postaları gönderme ve kullanıcıların tepkilerini izleme.

- Uygulama Güvenliği Testleri: Web uygulamalarının güvenlik açıklarını test etmek için kullanılabilir. Metasploit, web uygulamalarındaki yaygın açıklarını tespit etmek ve exploitler kullanarak bu açıkları istismar etmek için çeşitli modüller sunar.

## Örnek Senaryo:

Bir şirket, ağ güvenliğini test etmek için etik hackerlarla işbirliği yapmak istiyor. Metasploit Framework kullanılarak şirketin ağ güvenliği değerlendirilecektir.

1. İlk aşamada, etik hackerlar, şirketin IP aralığında bulunan tüm sistemleri tespit etmek için Nmap gibi bir tarama aracı kullanırlar.

2. Daha sonra, etik hackerlar, tespit edilen sistemlerin güvenlik açıklarını belirlemek için Nessus veya OpenVAS gibi güvenlik tarama araçlarını kullanabilirler.

3. Metasploit Framework kullanılarak şirketin ağına yönelik exploitler ve payloadlar hazırlanır.

4. Etik hackerlar, hazırlanan exploitleri şirketin sistemlerinde test eder ve potansiyel olarak etkilenen sistemleri belirler.

5. Şirketin sistem yöneticilerine güvenlik açıkları raporu sunulur ve kritik güvenlik açıkları giderilir.

Bu senaryoda, Metasploit Framework, şirketin ağ güvenliğini değerlendirmek ve potansiyel güvenlik açıklarını tespit etmek için kullanılmıştır. Böylece şirket, güvenlik zayıf noktalarını tespit ederek, saldırılara karşı daha iyi korunabilir hale gelir.

<a href="https://www.metasploit.com/" target="_blank">Metasploit</a>

<hr>

# Kismet

Kismet, kablosuz ağların (Wi-Fi ağlarının) keşfi ve izlenmesi için kullanılan bir kablosuz ağ izleme aracıdır. Kismet, ağ yöneticilerine, güvenlik uzmanlarına ve etik hackerlara kablosuz ağlardaki istenmeyen cihazları tespit etme ve ağ trafiğini analiz etme olanağı sağlar. Aynı zamanda kablosuz ağ güvenlik açıklarını belirlemek için kullanılır.

Kismet, aşağıdaki ana özelliklere sahiptir:

1. Pasif ve Aktif Modlar: Kismet, kablosuz ağlardaki veri trafiğini dinlemek için pasif mod ve aktif tarama yapmak için aktif mod olmak üzere iki farklı tarama yöntemi sunar.

2. Kanal Taraması: Kismet, belirli bir kanalda veya tüm kanallarda kablosuz ağları taramak için kullanılabilir. Bu, kablosuz ağlar hakkında kapsamlı bir bilgi toplamak için önemlidir.

3. Ağ İzleme ve Yönetimi: Kismet, etraftaki kablosuz ağları sürekli olarak izler ve keşfeder. Ağ yöneticileri ve güvenlik uzmanları, ağ trafiğini anlamak ve tespit edilmemiş ağlara karşı korunmak için bu bilgileri kullanabilir.

4. SSID Gizleme: Kismet, SSID'si gizlenmiş kablosuz ağları bile tespit edebilir ve kullanıcıya bu ağların bilgilerini sunar.

5. MAC Adresi Tespiti: Kismet, tarama sırasında cihazların MAC adreslerini tespit eder ve bu sayede cihazların kimliklerini belirler.

6. Veri Paketi Yakalama: Kismet, yakalanan veri paketlerini analiz edebilir ve kullanıcılara paketlerle ilgili ayrıntılı bilgi sunar.

Kismet, genellikle kablosuz ağ güvenliği testleri ve ağ performansı değerlendirmeleri için kullanılır. Örneğin, bir şirketin kablosuz ağındaki güvenlik açıklarını tespit etmek veya ağdaki istenmeyen cihazları ve potansiyel tehditleri belirlemek için Kismet kullanılabilir.

Ancak, unutmayın ki kablosuz ağları izlemek ve trafiği dinlemek yasa dışı olabilir ve izinsiz kullanım etik olmayan ve yasalara aykırıdır. Bu nedenle, Kismet gibi kablosuz ağ izleme araçları yalnızca yasal ve etik güvenlik testleri veya kişisel eğitim amaçları için kullanılmalıdır.

<a href="https://www.kismetwireless.net/" target="_blank">Kismet</a>

<hr>

# John the Ripper (John)

"John the Ripper" (kısaca John), parola kırma ve parola analizi için kullanılan ücretsiz ve açık kaynaklı bir güvenlik aracıdır. Parola kırma, bir sisteme veya hesaba yönelik parolayı tahmin ederek veya deneyerek çözme işlemidir. John the Ripper, parola kırma saldırıları yaparak şifreleme algoritmalarını çözmeye ve parolaları tespit etmeye çalışır.

John the Ripper, birçok şifreleme algoritmasını destekler ve aşağıdaki türdeki parola saldırıları için kullanılabilir:

1. Brute Force (Kaba Kuvvet) Saldırısı: John, tüm olası kombinasyonları deneyerek parolayı tahmin eder. Bu yöntem, küçük ve basit parolaların kırılmasında etkili olabilir, ancak uzun ve karmaşık parolaların kırılması için zaman alabilir.

2. Sözlük Saldırısı: John, belirli bir sözlük dosyasındaki kelimeleri veya ifadeleri kullanarak parolaları deneyebilir. Bu yöntem, yaygın kullanılan veya basit parolaların çoğunu tespit etmede etkilidir.

3. Hybrid Saldırısı: John, bir sözlük saldırısını kaba kuvvet saldırısı ile birleştirir. Bu, önceden tanımlanmış bir sözlük listesine ek olarak çeşitli eklemelerle parolaları deneme sürecidir.

John the Ripper, Linux, Windows, macOS ve diğer işletim sistemleri üzerinde çalışabilir. Ayrıca, grafik arayüzleri ve komut satırı arayüzü seçenekleri de vardır.

John the Ripper gibi parola kırma araçları, yalnızca yasal ve etik güvenlik testleri veya kişisel eğitim amaçları için kullanılmalıdır. Yasadışı veya kötü niyetli amaçlarla kullanmak, yasaları ihlal eder ve ciddi sonuçlar doğurabilir.

## Kullanım

1. Sözlük Saldırısı Kullanımı:

```bash
john --wordlist=sözlük_dosyası.txt şifrelenmiş_dosya
```

Bu komut, belirtilen "sözlük_dosyası.txt" içindeki kelimeleri kullanarak "şifrelenmiş_dosya" içindeki şifrelenmiş parolaları çözmeye çalışır. Sözlük dosyası, parola adaylarını içeren bir metin dosyasıdır.

2. Brute Force (Kaba Kuvvet) Saldırısı Kullanımı:

```bash
john --incremental şifrelenmiş_dosya
```

Bu komut, tüm olası kombinasyonları deneyerek "şifrelenmiş_dosya" içindeki şifrelenmiş parolaları çözmeye çalışır.

3. Hybrid Saldırısı Kullanımı:

```bash
john --wordlist=sözlük_dosyası.txt --rules şifrelenmiş_dosya
```

Bu komut, belirtilen "sözlük_dosyası.txt" içindeki kelimeleri kullanarak "şifrelenmiş_dosya" içindeki şifrelenmiş parolaları çözmeye çalışır. Ayrıca, çeşitli eklemelerle parolaları denemek için "rules" parametresini kullanır.

<a href="https://github.com/openwall/john" target="_blank">John</a>

<hr>

# Armitage

Metasploit Framework'ün kullanımını kolaylaştıran grafik arayüzlü bir araçtır. Metasploit Framework, güvenlik testleri ve penetrasyon testleri için kullanılan popüler bir açık kaynaklı güvenlik çerçevesidir. Metasploit, güvenlik uzmanları, etik hackerlar ve sistem yöneticileri tarafından kullanılan güçlü bir araçtır, ancak komut satırı tabanlıdır ve karmaşık olabilir. Armitage, bu süreci kolaylaştırarak kullanıcıların Metasploit'i daha etkin ve görsel bir şekilde kullanmalarına yardımcı olur.

Armitage, aşağıdaki temel özelliklere sahiptir:

1. Grafik Arayüz: Armitage, kullanıcı dostu bir grafik arayüzü sağlar, böylece Metasploit'in işlevlerini daha sezgisel ve kolay anlaşılır bir şekilde kullanabilirsiniz.

2. Hedef Keşfi: Armitage, ağdaki hedef sistemleri taramak ve keşfetmek için Metasploit'in özelliklerini kullanır.

3. Exploit Seçimi: Armitage, tespit edilen hedef sistemlere yönelik uygun exploitleri seçmeyi kolaylaştırır ve exploit seçeneklerini sunar.

4. Payload Yönetimi: Armitage, kullanıcıların çeşitli payloadları kolayca yönetmelerine ve hedef sistemlere göndermelerine olanak tanır.

5. Script ve Modül Yönetimi: Armitage, Metasploit'in script ve modüllerini yönetmek için kullanılabilir ve kullanıcılara farklı senaryoları uygulamalarında yardımcı olur.

6. Çoklu Saldırı Koordinasyonu: Armitage, birçok hedefe aynı anda saldırmak ve saldırıları koordine etmek için kullanılabilir.

<a href="https://github.com/r00t0v3rr1d3/armitage" target="_blank">Armitage</a>

<hr>

# Maltego

Maltego, güvenlik analizi ve veri keşfi için kullanılan bir veri madenciliği ve görselleştirme aracıdır. Maltego, açık kaynaklı bir topluluk sürümü olan "Maltego CE" ve ticari bir sürüm olan "Maltego Classic" olmak üzere iki sürümde bulunur. Ticari sürüm, daha gelişmiş özellikler ve destek içerirken, topluluk sürümü ücretsiz olarak kullanılabilir ve birçok temel görevi yerine getirebilir.

Maltego, bilgi toplamak ve analiz etmek için çeşitli veri kaynaklarından veri alır ve bu verileri görsel olarak ilişkilendirir. Bu, ağ güvenlik analizi, siber tehdit istihbaratı, dijital forensik çalışmaları ve açık kaynak istihbaratı gibi çeşitli alanlarda kullanılabilir.

Maltego'nun temel özellikleri şunlardır:

1. Veri Keşfi: Maltego, hedefle ilgili çeşitli veri kaynaklarından veri alarak hedef hakkında kapsamlı bir veri profilini oluşturur. Bu veri kaynakları, açık kaynaklar, sosyal medya, alan adları, IP adresleri, e-posta adresleri, WHOIS bilgileri, hedefin bağlantıları ve daha fazlasını içerebilir.

2. Görselleştirme: Maltego, keşfedilen verileri ağaçlar, grafikler ve ilişkisel diyagramlarla görsel olarak gösterir. Bu, verilerin daha kolay anlaşılmasına ve bağlantıların hızlı bir şekilde analiz edilmesine yardımcı olur.

3. Dönüşüm: Maltego, alınan verileri farklı formatlara dönüştürmek için dönüşüm araçları sağlar. Bu, farklı veri kaynaklarının ve sistemlerin birbiriyle uyumlu olmasını sağlar.

4. İzleme ve İstihbarat Analizi: Maltego, izleme ve tehdit istihbaratı için veri toplayarak, güvenlik uzmanlarının ve analistlerin tehditler ve saldırılar hakkında daha iyi bilgi sahibi olmasına yardımcı olur.

Maltego, güvenlik uzmanları, siber tehdit analistleri, dijital forensik uzmanları, yasa uygulayıcılar ve istihbarat analistleri gibi birçok farklı alandaki profesyoneller tarafından kullanılır.

<a href="https://www.maltego.com/" target="_blank">Maltego</a>

https://beefproject.com/

<hr>

# Beef-XSS

BeEF (Browser Exploitation Framework) bir güvenlik aracıdır ve XSS (Cross-Site Scripting) saldırıları için kullanılır. BeEF, açık kaynaklı bir güvenlik çerçevesidir ve web tarayıcılarını hedef alarak kullanıcıları manipüle etmek için kullanılır. XSS saldırıları, web uygulamalarındaki güvenlik açıklarını kullanarak kötü niyetli betiklerin tarayıcılar üzerinde çalıştırılmasıyla gerçekleştirilir. BeEF, bu tür saldırıları otomatize eder ve saldırganlara tarayıcı tabanlı saldırıları daha etkin bir şekilde yürütmelerine olanak tanır.

BeEF'in temel özellikleri şunlardır:

1. Browser Tabanlı Saldırılar: BeEF, hedef kullanıcıların web tarayıcıları üzerinde çeşitli saldırılar gerçekleştirir. Bu saldırılar, kullanıcıların oturum açma bilgilerini çalmak, zararlı içerikleri enjekte etmek, erişim kontrollerini atlamak ve tarayıcıyı uzaktan kontrol etmek gibi farklı amaçlarla yapılabilir.

2. JavaScript Tabanlı: BeEF, JavaScript tabanlı bir çerçeve olduğu için web tarayıcılarında çalışır ve tarayıcıya entegre edilmiş birçok işlevi kullanarak saldırılar gerçekleştirir.

3. Payload Yönetimi: BeEF, hedef tarayıcılara enjekte edilecek zararlı betikleri ve diğer yükleri yönetir. Bu sayede saldırganlar, çeşitli saldırılar için özelleştirilmiş yükler oluşturabilir ve yönetebilir.

4. Sosyal Mühendislik: BeEF, sosyal mühendislik saldırılarına yardımcı olur ve hedef kullanıcıları manipüle etmek için çeşitli taktikler kullanır.

5. XSS Zafiyetlerinin Keşfi: BeEF, hedef web uygulamalarındaki XSS zafiyetlerini tespit etmek ve bunları kullanmak için kullanılabilir.

BeEF, siber güvenlik uzmanları, etik hackerlar ve siber güvenlik ekipleri tarafından kullanılarak web uygulamalarının güvenliğini değerlendirmek ve güvenlik açıklarını tespit etmek için kullanılabilir. Ancak, unutulmamalıdır ki bu tür araçlar yalnızca yasal ve etik sınırlar içinde kullanılmalıdır. Yasadışı veya kötü niyetli amaçlarla kullanmak, yasaları ihlal eder ve ciddi sonuçlara yol açabilir.

<a href="https://beefproject.com/" target="_blank">Beef-XSS</a>

<hr>

# Nikto

Nikto, web sunucularını ve web uygulamalarını güvenlik açıklarını tespit etmek için kullanılan bir açık kaynaklı güvenlik tarayıcısıdır. Nikto, web sunucularını otomatik olarak tarar ve yaygın güvenlik açıklarını ve zayıf noktaları tespit etmek için çeşitli güvenlik testleri gerçekleştirir. Bu tarama süreci, web uygulamalarının ve sunucularının güvenliğini değerlendirmek ve potansiyel tehditleri belirlemek için kullanılır.

Nikto'nun temel özellikleri şunlardır:

1. Web Sunucu Taraması: Nikto, hedef web sunucusunu taramak için HTTP protokolünü kullanır ve sunucu hakkında çeşitli bilgileri elde eder.

2. Güvenlik Açıkları Taraması: Nikto, yaygın güvenlik açıklarını ve zayıf noktaları tespit etmek için hedef web uygulamasında ve sunucuda farklı testler yapar. Bu açıklar, güncel olmayan yazılımlar, açık yönetici panelleri, zararlı içeriklerin varlığı, izin verilen yönlendirmelerin olmaması ve daha fazlasını içerebilir.

3. HTTP Sunucu Ayarları ve Güvenlik İhlalleri: Nikto, hedef web sunucusunun ayarlarını ve güvenlik politikalarını değerlendirir ve ihlalleri raporlar.

4. SSL/TLS Denetimi: Nikto, web sunucularının SSL/TLS sertifikalarını kontrol eder ve şifreleme ayarlarını değerlendirir.

5. Özelleştirilebilir Tarama Seçenekleri: Nikto, kullanıcılara tarama için çeşitli seçenekler ve parametreler sunar, böylece taramayı özelleştirme ve odaklanma imkanı sağlar.

Nikto, ağ yöneticileri, güvenlik uzmanları, etik hackerlar ve siber güvenlik ekipleri tarafından web uygulamalarının ve sunucularının güvenlik durumunu değerlendirmek için kullanılır. Nikto, güvenlik testleri yaparken hedef sunucu ve web uygulamalarına yüksek trafik oluşturduğundan, izin alınmayan veya etik olmayan kullanımlardan kaçınılmalıdır. Nikto'nun yalnızca yasal ve etik sınırlar içinde kullanılması önemlidir.

<a href="https://github.com/sullo/nikto" target="_blank">Nikto</a>

<hr>

# Aircrack-ng

Aircrack-ng, kablosuz ağ güvenliği testleri için kullanılan bir dizi aracı içeren popüler bir açık kaynaklı güvenlik çerçevesidir. Aircrack-ng, Wi-Fi şifrelerini kırmak, kablosuz ağlarda güvenlik açıklarını tespit etmek ve kablosuz ağ trafiğini izlemek gibi çeşitli kablosuz ağ güvenlik testleri yapmak için kullanılır. Bu çerçeve, ağ güvenlik uzmanları, etik hackerlar ve güvenlik araştırmacıları tarafından kablosuz ağların güvenlik açıklarını değerlendirmek için kullanılır.

## Aircrack-ng'nin temel bileşenleri ve özellikleri şunlardır:

- airodump-ng: Kablosuz ağ trafiğini izlemek ve toplamak için kullanılır. Bu, hedef ağlar hakkında bilgi toplamak ve kullanıcılarını tanımak için kullanılabilir.

- aireplay-ng: Kablosuz ağlarda paket enjeksiyonu yapmak ve kablosuz trafiği manipüle etmek için kullanılır. Özellikle, WEP ve WPA/WPA2 şifrelerini kırmak için kullanılan deauth ve ARP replay saldırılarını gerçekleştirmek için kullanılır.

- aircrack-ng: Kapsamlı bir WEP ve WPA/WPA2 şifre kırma aracıdır. Ağda toplanan şifrelenmiş paketlerin analizini yaparak şifreleri tahmin etmeye çalışır.

- airmon-ng: Kablosuz adaptörü monitör moduna geçirmek için kullanılır. Monitör modunda, kablosuz ağ trafiği dinlenebilir ve analiz edilebilir.

- airbase-ng: Sahte kablosuz erişim noktaları oluşturmak için kullanılır. Bu, kablosuz ağ saldırılarında sosyal mühendislik ve MITM (Man-in-the-Middle) saldırıları için kullanılabilir.

Aircrack-ng, yalnızca yasal ve etik güvenlik testleri veya kişisel eğitim amaçları için kullanılmalıdır. Kablosuz ağları izinsiz olarak kırmak, izinsiz erişim noktaları oluşturmak veya izinsiz ağlara saldırmak yasa dışıdır ve ciddi yasal sonuçlara yol açabilir. Aircrack-ng gibi kablosuz güvenlik araçları yalnızca meşru ve izinli kullanımlarda kullanılmalıdır.

<a href="https://www.aircrack-ng.org/" target="_blank">Aircrack-ng</a>

<hr>

# Crunch

Crunch, açık kaynaklı bir parola jeneratörüdür. Kullanıcıların belirli kriterlere göre özelleştirilmiş parola listeleri oluşturmalarına olanak tanır. Bu, güvenlik testleri ve parola saldırıları için kullanışlı bir araçtır.

## Crunch'un temel özellikleri şunlardır:

- Parola Kriterleri: Crunch, kullanıcının belirlediği uzunluk, karakter seti ve desenlere göre parolalar oluşturabilir. Kullanıcı, büyük harf, küçük harf, rakam ve özel karakterleri dahil ederek veya hariç tutarak parolaları özelleştirebilir.

- Tersine Çevirme: Crunch, oluşturulan parola listesini tersine çevirerek belirli durumlar için parolaları özelleştirebilir.

- Sıralama: Crunch, parola listesini belirli bir sırayla oluşturabilir, tersine çevirebilir veya karıştırabilir.

- Çıktı Biçimleri: Crunch, oluşturulan parolaları metin dosyalarına kaydetmek için farklı çıktı biçimleri sunar.

<a href="https://sourceforge.net/projects/crunch-wordlist/" target="_blank">Crunch</a>

<hr>

# Sqlmap

Sqlmap, web uygulamalarında SQL enjeksiyonu tespiti ve saldırısı yapmak için kullanılan popüler bir açık kaynaklı araçtır. SQL enjeksiyonu, web uygulamalarının güvenlik açıklarından biridir ve kötü niyetli kişilerin web uygulamasının veritabanına yetkisiz erişim sağlayabileceği veya veritabanını manipüle edebileceği bir güvenlik açığıdır.

Sqlmap, web uygulamalarında SQL enjeksiyonu tespit etmek için otomatik olarak çeşitli teknikler ve saldırı vektörleri kullanır. Bu, web uygulamalarında SQL enjeksiyonu açıkları olup olmadığını belirlemeye yardımcı olur. Eğer açık varsa, sqlmap, bu açıkları sömürmek ve veritabanını manipüle etmek için SQL saldırıları gerçekleştirir.

## Sqlmap'un temel özellikleri şunlardır:

- Otomatik Algılama: Sqlmap, SQL enjeksiyon açıklarını otomatik olarak algılar ve tespit eder. Birden fazla tespit yöntemi kullanarak, enjeksiyon olasılığını ve etkinliğini değerlendirir.

- Veritabanı Saldırıları: Sqlmap, enjekte edilebilir parametreleri kullanarak veritabanını hedef alarak veri çalma, veri tablosu bilgilerini çıkarma ve hatta veritabanı sistemini tamamen ele geçirme gibi saldırıları gerçekleştirebilir.

- Veritabanı Keşfi: Sqlmap, hedef veritabanının yapısal bilgilerini (tablo adları, sütunlar, vb.) ve kullanıcı kimlik bilgilerini (veritabanı kullanıcı adları ve şifreleri) tespit etmek için kullanılabilir.

- Komut Yürütme: Sqlmap, bazı durumlarda SQL enjeksiyonu ile komut yürütme saldırıları gerçekleştirebilir ve hedef sunucuda komutları çalıştırabilir.

<a href="https://sqlmap.org/" target="_blank">Sqlmap</a>

<hr>

# Arpwatch

Arpwatch, bir ağ güvenlik aracıdır ve yerel ağınızda ARP (Address Resolution Protocol) aktivitelerini izlemek ve analiz etmek için kullanılır. ARP, bir IP adresini fiziksel bir MAC adresine eşleştiren protokoldür. Arpwatch, ARP trafiğini izler ve ağdaki MAC adresi/IP adresi çiftlerini kaydederek ve değişiklikleri takip ederek ağdaki potansiyel güvenlik tehditlerini veya hataları belirlemeye yardımcı olur.

## Arpwatch'un temel işlevleri şunlardır:

- ARP Aktivitelerinin İzlenmesi: Arpwatch, ağdaki tüm ARP paketlerini izleyerek ve bunları kaydederek ağdaki MAC adresi/IP adresi eşlemelerini takip eder.

- ARP Cevaplarının Analizi: Arpwatch, beklenmeyen veya potansiyel saldırıya işaret eden ARP cevaplarını (örneğin ARP zehirlemesi) tespit edebilir.

- IP Adresi Değişikliklerinin Takibi: Arpwatch, ağdaki cihazların IP adreslerindeki değişiklikleri tespit eder ve bu durumları izler.

- E-posta Uyarıları: Arpwatch, ağdaki değişiklikler veya potansiyel saldırılar hakkında sistem yöneticilerini uyarı e-postaları gönderebilir.

<a href="https://ee.lbl.gov/" target="_blank">Arpwatch</a>

<hr>

# Wpscan

WPScan, WordPress tabanlı web sitelerinin güvenlik taramalarını gerçekleştirmek için kullanılan açık kaynaklı bir güvenlik aracıdır. WordPress, popüler ve yaygın olarak kullanılan bir içerik yönetim sistemi (CMS) olduğu için saldırganlar tarafından hedef alınma olasılığı yüksektir. WPScan, WordPress sitelerindeki güvenlik açıklarını ve zayıf noktaları tespit etmek ve düzeltmek için kullanılan etkili bir araçtır.

## WPScan'in temel özellikleri şunlardır:

- WordPress Güvenlik Zafiyet Taraması: WPScan, hedef WordPress sitesini otomatik olarak tarar ve potansiyel güvenlik açıklarını tespit eder. Bu, güncellemeleri eksik bırakılmış eklentiler, temalar, WordPress sürümü gibi zayıf noktaları belirlemeye yardımcı olur.

- Eklenti ve Tema Kontrolü: WPScan, hedef WordPress sitesinde kullanılan eklenti ve temaların güvenlik durumunu değerlendirmek için eklenti ve tema bilgilerini kontrol eder.

- Kullanıcı Doğrulama Saldırıları: WPScan, kullanıcı adı ve şifre kombinasyonları ile kullanıcı doğrulama saldırıları gerçekleştirir ve zayıf şifreleri tespit edebilir.

- Güvenlik Duvarı ve Engelleme Tespiti: WPScan, hedef WordPress sitesinin arkasında bir güvenlik duvarı veya IP engelleme mekanizması olup olmadığını tespit eder.

- Bilgi Toplama: WPScan, hedef WordPress sitesi hakkında çeşitli bilgileri toplar, örneğin, site yapısı, tema ve eklenti sürümleri, gibi bilgileri sağlar.

<a href="https://wpscan.com/" target="_blank">Wpscan</a>

<hr>

# Hashcat

Hashcat, açık kaynaklı ve hızlı bir parola kurtarma (cracking) aracıdır. Hashcat, parolaların veya şifrelenmiş verilerin üzerinde brute force (kaba kuvvet) ve sözlük saldırıları yaparak parola kurtarma işlemini gerçekleştirir. Özellikle hash (karma) değerleri kullanılarak depolanan şifrelerin kırılması için yaygın olarak kullanılır.

## Hashcat'in temel özellikleri şunlardır:

-Çoklu Algoritma Desteği: Hashcat, çeşitli algoritmalara (MD5, SHA-1, SHA-256, SHA-512, NTLM, vb.) dayalı hashleri kırmak için kullanılabilir.

-GPU Hızlandırma: Hashcat, grafik işlem birimlerini (GPU'ları) kullanarak parola kurtarma işlemlerini hızlandırır ve yüksek performans sağlar.

-Farklı Saldırı Modları: Hashcat, brute force (kaba kuvvet), sözlük saldırısı, mask saldırısı ve hibrit saldırı gibi farklı saldırı modları sunar.

-Özelleştirilebilir Kural Motoru: Hashcat, kullanıcıların parola deneme yöntemlerini ve kurallarını özelleştirmelerine olanak tanır.

-Parola Hafızası: Hashcat, denenen parolaların hafızasını kullanarak, aynı parolayı tekrar deneme ihtiyacını azaltır ve işlemi hızlandırır.

<a href="https://hashcat.net/hashcat/" target="_blank">Hashcat</a>

<hr>

# TCPDump

Tcpdump, ağ trafiğini izlemek ve analiz etmek için kullanılan bir komut satırı aracıdır. UNIX ve UNIX benzeri işletim sistemlerinde (Linux, macOS, BSD, vb.) yaygın olarak bulunur. Tcpdump, ağ paketlerini yakalar ve kullanıcının belirlediği filtrelerle bu paketleri analiz eder. Bu sayede ağ trafiğini anlamak, sorunları tespit etmek ve güvenlik analizleri yapmak için kullanılır.

## Tcpdump'un temel özellikleri şunlardır:

- Ağ Paketi Yakalama: Tcpdump, ağ trafiğini dinleyerek geçen ağ paketlerini yakalar. Bu paketler, verilerin, protokollerin ve bağlantıların analizini sağlar.

- Filtreleme: Tcpdump, kullanıcının belirlediği filtreleri kullanarak sadece belirli ağ paketlerini yakalamasını sağlar. Bu, trafiği belirli protokoller, kaynak ve hedef IP adresleri veya port numaralarına göre filtrelemek için kullanılabilir.

- Paketlerin Formatlanması: Tcpdump, yakalanan ağ paketlerini farklı formatlarda çıktılarla sunar. Örneğin, paketleri hexadecimal formatında, ASCII formatında veya daha anlaşılır şekilde göstermek için kullanılabilir.

- İstatistikler ve Raporlar: Tcpdump, yakalanan paketlere ilişkin istatistikler ve raporlar oluşturabilir. Bu, ağ trafiği yoğunluğu, iletişim sıklığı, hata oranları gibi verileri analiz etmek için kullanılabilir.

<a href="https://www.tcpdump.org/" target="_blank">TCPDump</a>

<hr>

# Ettercap

Ettercap, bir ağ saldırı aracı ve paket analiz programıdır. Temel olarak, yerel ağınızdaki (LAN) veri paketlerini izlemek, analiz etmek ve manipüle etmek için kullanılır. Ettercap, MITM (Man-in-the-Middle) saldırıları gerçekleştirebilir ve bu sayede ağdaki trafiği dinleyebilir ve değiştirebilir. Ayrıca, açık ağlardaki (public Wi-Fi gibi) diğer kullanıcılarla aranıza girerek verileri çalabilir veya saldırılar yapabilir.

## Ettercap'in temel özellikleri şunlardır:

- MITM Saldırıları: Ettercap, ağdaki trafiği yönlendirmek ve MITM saldırıları gerçekleştirmek için kullanılabilir. Bu sayede, saldırgan, verileri iki uç arasında geçerken dinleyebilir, değiştirebilir veya manipüle edebilir.

- Protokol Destekleri: Ettercap, çeşitli ağ protokollerini destekler ve bu protokoller üzerinde saldırılar yapabilir. Özellikle HTTP, FTP, SMTP, POP3, SSH, SSL, DNS gibi yaygın protokoller üzerinde saldırılar gerçekleştirebilir.

- Sesli Bildirimler: Ettercap, bazı durumlarda ağ trafiği analizi için sesli bildirimler sunar. Bu, ağda belirli olayların gerçekleştiğini duymak için kullanılabilir.

- Arayüz ve Filtrasyon: Ettercap, kullanıcı dostu bir arayüze sahiptir ve paket filtreleme ve analiz işlemleri için çeşitli filtre seçenekleri sunar.

<a href="https://www.ettercap-project.org/" target="_blank">Ettercap</a>

<hr>

# Autopsy

Autopsy, dijital veri analizi ve adli bilişim incelemeleri için kullanılan açık kaynaklı bir dijital olay inceleme (DFIR) aracıdır. Adli bilişim, suçlara ve diğer yasadışı faaliyetlere ilişkin dijital delilleri toplamak, analiz etmek ve yasal olarak kullanılabilir şekilde raporlamak için bilgisayar korsanları, kolluk kuvvetleri ve diğer adli uzmanlar tarafından kullanılır.

## Autopsy'nin temel özellikleri şunlardır:

- Disk ve Veri İmajları İnceleme: Autopsy, disk imajları (örneğin, harddisk veya USB bellek görüntüleri) ve diğer dijital veri imajlarını açarak incelemeyi sağlar.

- Otomatik İnceleme Modu: Autopsy, adli olay incelemelerini kolaylaştırmak için otomatik inceleme modu sunar. Bu mod, olaya özgü filtreleri ve analizleri otomatik olarak gerçekleştirir.

- Veri Arama ve İndeksleme: Autopsy, büyük miktarda dijital veriyi hızlı bir şekilde arama ve indeksleme yeteneklerine sahiptir. Bu sayede, olayla ilgili önemli delillerin tespit edilmesi kolaylaşır.

- Dosya ve E-posta Analizi: Autopsy, dosyaların ve e-postaların içeriğini analiz ederek olaya ilişkin önemli bilgileri ortaya çıkarır.

- Güçlü Raporlama: Autopsy, bulunan delilleri kapsamlı bir şekilde raporlayabilir ve sunabilir. Bu raporlar, yasal süreçlerde ve mahkemelerde kullanılabilecek nitelikte olabilir.

<a href="https://www.ettercap-project.org/" target="_blank">Autopsy</a>

<hr>

# Sherlock

Sherlock, bir kullanıcı adını veya takma adı çeşitli sosyal medya platformlarında ve diğer web sitelerinde aramak için kullanılan açık kaynaklı bir araçtır. Bu araç, bir kişinin belirli bir kullanıcı adıyla hangi platformlarda hesaplarının olduğunu bulmayı kolaylaştırır.

## Sherlock'ın temel özellikleri şunlardır:

- Kullanıcı Adı Arama: Sherlock, kullanıcının belirttiği bir kullanıcı adını (veya takma adı) çeşitli sosyal medya platformlarında ve web sitelerinde otomatik olarak arar.

- Çoklu Platform Desteği: Sherlock, bir kullanıcı adını aynı anda birden fazla platformda arayabilir. Bu platformlar arasında Twitter, Instagram, Facebook, GitHub, LinkedIn, Reddit, Snapchat ve daha birçok sosyal medya ve web sitesi bulunur.

- Basit ve Hızlı Arama: Sherlock, basit ve hızlı bir arayüze sahiptir ve kullanıcının belirlediği kullanıcı adını hızlı bir şekilde arayarak sonuçları gösterir.

<a href="https://github.com/sherlock-project/sherlock" target="_blank">Sherlock</a>

<hr>

# Netcat

Netcat, çeşitli ağ bağlantıları oluşturmak, ağ hizmetlerini test etmek, ağda veri transferi yapmak ve diğer ağ işlemlerini gerçekleştirmek için kullanılan bir komut satırı aracıdır. Netcat, çapraz platform destekli bir ağ aracıdır ve birçok işletim sisteminde kullanılabilir.

## Netcat'in temel özellikleri şunlardır:

- Bağlantı Kurma: Netcat, TCP veya UDP protokollerini kullanarak uzaktaki bir bilgisayara bağlanmayı sağlar.

- Sunucu Modu: Netcat, TCP veya UDP üzerinde belirli bir portu dinleyerek başka bir cihazdan bağlantı alabilir.

- Veri Transferi: Netcat, iki bilgisayar arasında metin veya dosya gibi verileri kolayca transfer etmek için kullanılabilir.

- Port Tarama: Netcat, belirli bir IP adresi ve port aralığında port tarama işlemleri yapabilir ve hedef sistemde açık portları tespit edebilir.

- Geriye Doğru Kabuk Alma (Reverse Shell): Netcat, bir hedef sistemde bir kabuk açmak için geriye doğru bağlantı kurabilir. Bu, güvenlik testleri ve sızma testlerinde yaygın olarak kullanılır.

<a href="http://www.stearns.org/nc/" target="\_blank">Netcat</a>

<hr>

# Burpsuite

Burp Suite, web uygulama güvenlik testleri için kullanılan popüler bir güvenlik aracıdır. Web uygulamalarının güvenlik açıklarını tespit etmek ve analiz etmek için etkili bir şekilde kullanılabilir. Burp Suite, Proxy, Scanner, Spider, Repeater, Intruder, Sequencer ve Decoder gibi bir dizi araç içerir, böylece web uygulamalarının güvenlik testlerini tamamlamak için çeşitli özelliklere sahiptir.

## Burp Suite'in temel özellikleri şunlardır:

- Proxy: Burp Suite, web tarayıcısı ve web uygulaması arasında bir proxy olarak çalışabilir. Bu sayede, HTTP/HTTPS trafiğini dinleyebilir, değiştirebilir ve analiz edebilir. Bu özellik, web uygulamalarının güvenlik açıklarını tespit etmek için oldukça değerlidir.

- Scanner: Burp Suite, web uygulamalarında otomatik olarak güvenlik açıkları taraması yapar. Bu, SQL enjeksiyonu, XSS (Cross-Site Scripting), güvenlik duvarı bypass ve diğer yaygın web güvenlik açıklarını tespit etmek için kullanılır.

- Spider: Burp Suite, web uygulamasındaki tüm bağlantıları ve sayfaları taramak için Spider özelliğini içerir. Bu sayede, tarama kapsamını genişleterek diğer potansiyel güvenlik açıklarını keşfetmeye yardımcı olur.

- Repeater: Burp Suite, HTTP isteklerini ve yanıtlarını tekrarlamak ve değiştirmek için Repeater aracını sunar. Bu, belirli güvenlik açıklarını doğrulamak veya özelleştirilmiş saldırıları gerçekleştirmek için kullanılabilir.

- Intruder: Burp Suite, belirli parametreleri değiştirerek yinelenen saldırılar gerçekleştiren Intruder özelliğine sahiptir. Bu, brute force saldırıları ve diğer özelleştirilmiş saldırılar için kullanılabilir.

<a href="https://portswigger.net/" target="\_blank">Burpsuite</a>

<hr>

# Gobuster

Gobuster, açık kaynaklı bir dizin tarama ve keşif aracıdır. Web uygulamalarının veya web sitelerinin belirli bir sunucuda veya dizinde açıkta bulunan dizinleri ve dosyaları taramak için kullanılır. Gobuster, dizin keşfi yaparak web sunucularında olası güvenlik açıklarını tespit etmek ve dosya yapılarını anlamak için etkili bir araçtır.

## Gobuster'in temel özellikleri şunlardır:

- Dizin Tarama: Gobuster, belirtilen hedef URL'de dizinleri ve dosyaları taramak için kullanılır. Bu sayede sunucuda açıkta kalmış dosyalar, dizinler veya hata sayfaları gibi potansiyel güvenlik zafiyetleri tespit edilebilir.

- Dizin Listesi: Gobuster, tarama için kullanılacak olan dizinlerin veya dosyaların liste dosyalarını kabul eder. Bu liste dosyaları, kullanıcı tarafından belirlenerek taramanın kapsamı özelleştirilebilir.

- Paralel Tarama: Gobuster, dizin tarama işlemini paralel olarak yürütme özelliği sunar. Bu sayede tarama süresi kısaltılabilir ve hızlı sonuçlar elde edilebilir.

- HTTP ve HTTPS Desteği: Gobuster, HTTP ve HTTPS protokollerini destekler. Böylece web sitelerindeki güvenlik zafiyetlerini hem açık hem de şifreli bağlantılarda taramak mümkün olur.

<a href="https://github.com/OJ/gobuster" target="\_blank">Gobuster</a>

<hr>

# Mimikatz

Mimikatz, açık kaynak kodlu olmayan bir araç olarak başlamış ve sonradan açık kaynak kodlu bir versiyonu da geliştirilen, Windows işletim sistemi üzerindeki kimlik doğrulama verilerini çalma ve manipüle etme yeteneğine sahip güvenlik aracıdır. Bu araç, gelişmiş yetkilendirme saldırıları ve kimlik doğrulama bilgilerinin alınması amacıyla kullanılır.

## Mimikatz'ın temel özellikleri şunlardır:

- Parola Çalma: Mimikatz, Windows işletim sistemindeki parolaları ve parola karma değerlerini (NTLM hash) alabilir. Böylece, parola çalma saldırıları gerçekleştirilir.

- Kerberos Tokenlerini Almak: Mimikatz, Kerberos yetkilendirme işlemleri için kullanılan kimlik doğrulama belgeleri olan Kerberos tokenlerini çalabilir ve manipüle edebilir. Bu sayede, yetkileri artırmak veya kimlik doğrulama mekanizmalarını aşmak mümkün olabilir.

- Ticket İşlemleri: Mimikatz, Windows işletim sistemi tarafından oluşturulan ve kullanıcıların kimlik doğrulama bilgilerini içeren Kerberos biletlerini yönetebilir.

- LSA İşlemleri: Mimikatz, Windows LSA (Local Security Authority) alt sistemine saldırılar gerçekleştirebilir ve kimlik doğrulama verilerini alabilir.

Mimikatz, özellikle "Pass-the-Hash" ve "Pass-the-Ticket" saldırıları gibi yetkileri yükseltme saldırıları için kullanılır. Bu tür saldırılar, yetkilendirme bilgilerini çalarak ve kimlik doğrulama mekanizmalarını yanıltarak hedef sistemlerde daha yüksek yetkilere sahip olmaya çalışır.

<a href="https://blog.gentilkiwi.com/mimikatz" target="\_blank">Mimikatz</a>

<hr>

# Responder

Responder, Windows tabanlı bir saldırı aracıdır ve yerel ağlarda NTLM (NT LAN Manager) hash kimlik doğrulama bilgilerini toplamak için kullanılır. NTLM, eski bir kimlik doğrulama protokolüdür ve yerel ağlarda hala kullanılmaktadır. Responder, ağda NTLM kimlik doğrulama trafiği algıladığında, sahte yanıtlar vererek hedef sistemlerden NTLM hashleri çalabilir.

## Responder'ın temel özellikleri şunlardır:

- NTLM Hash Çalma: Responder, ağda NTLM kimlik doğrulama trafiğini dinleyerek, hedef sistemlerden kullanıcı adlarına karşılık gelen NTLM hashleri alabilir.

- LLMNR ve NBT-NS Sahte Cevapları: Responder, Link-Local Multicast Name Resolution (LLMNR) ve NetBIOS Name Service (NBT-NS) protokollerine sahte yanıtlar göndererek, hedef sistemlerden NTLM kimlik doğrulama trafiği çeker.

- Pass-the-Hash Saldırıları: Responder, topladığı NTLM hashleri kullanarak "Pass-the-Hash" saldırıları gerçekleştirebilir. Bu saldırı türü, NTLM hashleri ile kimlik doğrulama yaparak hedef sistemlere yetkili erişim sağlama yöntemidir.

<a href="https://github.com/lgandx/Responder" target="\_blank">Responder</a>

<hr>

# FFUF (Fuzz Faster U Fool)

FFUF (Fuzz Faster U Fool) açık kaynaklı bir web fuzzer aracıdır. FFUF, web uygulamalarında dizinler, dosyalar ve parametreler üzerinde brute force saldırıları gerçekleştirmek için kullanılır. Bu araç, web uygulamalarındaki güvenlik zafiyetlerini tespit etmek, dizinleri keşfetmek ve hedef web sunucularını test etmek için kullanışlıdır.

## FFUF'un temel özellikleri şunlardır:

- Basit ve Hızlı: FFUF, basit ve hızlı bir arayüze sahiptir ve hızlı bir şekilde büyük miktarlarda istekleri işleyebilir. Bu sayede web uygulamalarının dizinlerini veya parametrelerini brute force yöntemiyle tarayabilir.

- Dizin Tarama: FFUF, web sunucularında belirli bir dizin yapısını taramak için kullanılabilir. Bu, gizli dizinleri veya dosyaları bulmak için etkili bir yöntemdir.

- Parametre Fuzzing: FFUF, web uygulamalarında belirli parametreleri brute force saldırısıyla test etmek için kullanılabilir. Bu, SQL enjeksiyonu veya diğer parametre bağımlı güvenlik açıklarını tespit etmeye yardımcı olur.

- Yineleme ve Uzunluk Kontrolü: FFUF, belirli durumlar için isteklerin tekrarlanmasına ve isteklerin uzunluklarının kontrol edilmesine izin verir.

<a href="https://github.com/ffuf/ffuf" target="\_blank">FFUF</a>

<hr>

# TheHarvester

TheHarvester, açık kaynaklı bir istihbarat toplama (OSINT - Open Source Intelligence) aracıdır. TheHarvester, belirli bir hedefle ilgili açık kaynaklardan (internet üzerindeki açık bilgi kaynakları) veri toplamak ve hedefle ilgili bilgileri bulmak için kullanılır. Bu araç, sızma testleri ve güvenlik değerlendirmeleri sırasında hedefle ilgili önemli bilgileri toplamak için siber güvenlik uzmanları ve etik hackerlar tarafından kullanılır.

## TheHarvester'in temel özellikleri şunlardır:

- E-posta Adresi Tarama: TheHarvester, belirtilen hedefle ilişkili e-posta adreslerini toplamak için çeşitli açık kaynakları tarar. Bu, bir şirket veya kişiyle ilgili e-posta adreslerini bulmak için kullanılabilir.

- Alan Adı Tarama: TheHarvester, belirli bir alan adı (domain) ile ilişkili alt alan adlarını ve alt alan adlarının IP adreslerini bulmak için kullanılabilir.

- Kullanıcı Adı Tarama: TheHarvester, belirli bir kullanıcı adı ile ilişkili sosyal medya hesaplarını ve diğer açık kaynaklardaki kullanıcı adlarını bulmak için kullanılabilir.

- Güvenlik Açığı Tespiti: TheHarvester, belirli bir hedefle ilgili güvenlik açıklarını veya eksiklikleri tespit etmek için de kullanılabilir. Örneğin, hedefin açıkta kalmış bir sunucu adresi veya kötü yapılandırılmış DNS ayarları olup olmadığını tespit etmeye yardımcı olabilir.

<a href="https://github.com/laramies/theHarvester" target="\_blank">TheHarvester</a>

<hr>

# Wifite

Wifite, açık kaynaklı bir kablosuz ağ saldırı aracıdır ve Wi-Fi ağlarını kırmak ve test etmek için kullanılır. Wifite, WPA/WPA2 güvenlik protokollerini kırmak için otomatik olarak saldırılar gerçekleştirir ve şifreleri tahmin eder. Bu araç, güvenlik testleri veya sızma testleri sırasında kablosuz ağlardaki güvenlik açıklarını tespit etmek ve güçlendirmek için kullanılabilir.

## Wifite'in temel özellikleri şunlardır:

- Otomatik Mod: Wifite, WPA/WPA2 şifrelerini kırmak için otomatik modda çalışabilir. Bu, belirli bir hedef Wi-Fi ağında belirli bir şifre listesini otomatik olarak deneyerek saldırı gerçekleştirir.

- El Taraması Modu: Wifite, kullanıcıların belirli bir Wi-Fi ağını seçip belirli bir şifre listesiyle elle tarama yapmasına da izin verir.

- Brute Force Saldırıları: Wifite, WPA/WPA2 şifrelerini tahmin etmek için farklı şifre kombinasyonları deneyerek brute force saldırıları gerçekleştirir.

- WPS Saldırıları: Wifite, WPS (Wi-Fi Protected Setup) güvenlik protokolünü kırmak için saldırılar yapabilir. WPS, güvenlik açısından zayıf olduğu bilinen bir protokoldür.

<a href="https://github.com/kimocoder/wifite2" target="\_blank">Wifite</a>

<hr>

# Dirb

Dirb, açık kaynaklı bir web dizini keşif aracıdır. Web sitelerinin veya web uygulamalarının dizinlerini taramak ve dizinlerdeki mevcut dosyaları keşfetmek için kullanılır. Dirb, "Directory Buster" olarak da adlandırılır ve dizin keşfi için farklı sözlük saldırıları gerçekleştirir.

## Dirb'ın temel özellikleri şunlardır:

- Dizin Tarama: Dirb, belirli bir hedef web sitesi veya web uygulamasında dizinleri taramak için kullanılır. Bu, açıkta kalmış dizinleri veya dosyaları tespit etmeye yardımcı olur.

- Sözlük Saldırıları: Dirb, dizin ve dosya adlarını belirli bir sözlük dosyasındaki kelimelerle karşılaştırarak keşfetmeye çalışır. Bu, yaygın kullanılan dosya adları veya dizin adlarını tarayarak hedefteki potansiyel güvenlik zafiyetlerini bulmayı sağlar.

- Uzantı Filtreleme: Dirb, belirli dosya uzantılarını filtreleyerek yalnızca belirli türdeki dosyaları taramak için kullanılabilir. Örneğin, sadece .php uzantılı dosyaları taramak gibi.

<a href="https://dirb.sourceforge.net/" target="\_blank">Dirb</a>

<hr>

# Medusa

Medusa, açık kaynaklı ve çok hızlı bir parola kırma aracıdır. Medusa, kullanıcı adları ve parolalar üzerinde brute force saldırıları gerçekleştirerek, şifreleri çözmeye çalışır. Genellikle ağ ve servisler üzerinde oturum açma bilgilerini kırmak için kullanılır. Popüler servis protokollerini ve giriş yöntemlerini destekler.

## Medusa'nın temel özellikleri şunlardır:

- Çoklu Protokol Desteği: Medusa, farklı servisler ve protokoller için kullanıcı adı ve parola kırma saldırıları gerçekleştirebilir. Örneğin, SSH, FTP, HTTP POST formu, POP3, Telnet, SMB, RDP gibi popüler protokolleri destekler.

- Hızlı ve Paralel Tarama: Medusa, paralel işlem özelliği sayesinde çok hızlı bir şekilde kullanıcı adı ve parola denemelerini gerçekleştirir. Bu sayede verimli bir şekilde şifre kırma işlemleri yapabilir.

- Şifre Sözlüğü Desteği: Medusa, şifre kırma işlemleri için sözlük saldırıları yapar. Kullanıcılar, özelleştirilmiş şifre sözlükleri oluşturarak şifre denemelerini yapılandırabilir.

<a href="http://foofus.net/?page_id=51" target="\_blank">Medusa</a>

<hr>

# Impacket-Scripts

Impacket, Python programlama dilinde yazılmış açık kaynaklı bir ağ güvenlik araçları koleksiyonudur. Bu araçlar, ağ üzerindeki farklı protokollerle etkileşime geçmek ve güvenlik testleri yapmak için kullanılır. Impacket araçlarının içerisinde bir dizi script (betik) bulunmaktadır ve bu scriptler çeşitli ağ güvenlik testleri için kullanılmaktadır.

İmpacket scriptleri, ağ üzerinde çeşitli protokollerle etkileşim sağlamak, kimlik doğrulama mekanizmalarını test etmek, saldırılar gerçekleştirmek ve sızma testleri yapmak için kullanılabilir.

## Bazı yaygın Impacket scriptleri şunlardır:

- smbclient.py: SMB (Server Message Block) protokolünü kullanarak SMB sunucularıyla etkileşim sağlar. Dosya paylaşımları, dosya aktarımları ve SMB sunucularını test etmek için kullanılır.

- smbexec.py: Uzaktaki bir Windows makinesinde kod yürütmeyi sağlar. SMB aracılığıyla shell erişimi elde etmek için kullanılabilir.

- lookupsid.py: SMB üzerinden SID (Security Identifier) çözümleme yaparak, bir kullanıcının veya grubun SID değerini elde etmeye yarar.

- samrdump.py: Windows SAM (Security Account Manager) veritabanını çözer ve kullanıcı parolalarını elde etmek için kullanılır.

- getArch.py: Uzaktaki Windows bilgisayarının mimarisini belirlemeye yardımcı olur.

- secretsdump.py: Windows sistemlerinde yerel SAM veritabanını çözer ve kullanıcı kimlik bilgilerini elde etmek için kullanılır.

- ticketer.py: Kerberos bileti oluşturmayı ve Kerberos yetkilendirmesi için kullanılır.

<a href="https://www.kali.org/tools/impacket-scripts/" target="\_blank">Impacket Scripts from kali</a>

<hr>

# Dmitry

Dmitry, açık kaynaklı bir istihbarat toplama aracıdır (OSINT - Open Source Intelligence). Dmitry, hedef bir alan adı veya IP adresi hakkında çeşitli bilgileri toplamak ve hedef sistemle ilgili açık kaynaklardan veri elde etmek için kullanılır. Bu araç, sızma testleri veya güvenlik değerlendirmeleri sırasında hedeflerle ilgili önemli bilgileri tespit etmek için siber güvenlik uzmanları ve etik hackerlar tarafından kullanılır.

# Dmitry'nin temel özellikleri şunlardır:

- Alan Adı ve IP Adresi Tarama: Dmitry, belirli bir alan adı veya IP adresi hakkında çeşitli bilgileri taramak için kullanılır. Bu, hedefle ilgili temel bilgileri elde etmeye yardımcı olur.

- DNS Tarama: Dmitry, DNS (Domain Name System) bilgilerini ve DNS sunucularını taramak için kullanılabilir.

- WHOIS Sorgusu: Dmitry, belirli bir alan adı veya IP adresiyle ilişkili WHOIS bilgilerini sorgulamak için kullanılabilir.

- Port Tarama: Dmitry, belirli bir IP adresinde açık olan portları taramak için kullanılabilir.

- E-posta Tarama: Dmitry, belirli bir alan adıyla ilişkili e-posta adreslerini taramak için kullanılabilir.

- Subdomain Tarama: Dmitry, belirli bir alan adıyla ilişkili alt alan adlarını taramak için kullanılabilir.

<a href="https://www.mor-pah.net/index.php?file=projects/dmitry" target="\_blank">Dmitry</a>

<hr>

# Dirbuster

DirBuster, açık kaynaklı bir web dizini keşif aracıdır. Web sitelerinin veya web uygulamalarının dizinlerini taramak ve dizinlerdeki mevcut dosyaları keşfetmek için kullanılır. DirBuster, "Directory Buster" olarak da adlandırılır ve dizin keşfi için farklı sözlük saldırıları gerçekleştirir.

## DirBuster'in temel özellikleri şunlardır:

- Dizin Tarama: DirBuster, belirli bir hedef web sitesi veya web uygulamasında dizinleri taramak için kullanılır. Bu, açıkta kalmış dizinleri veya dosyaları tespit etmeye yardımcı olur.

- Sözlük Saldırıları: DirBuster, dizin ve dosya adlarını belirli bir sözlük dosyasındaki kelimelerle karşılaştırarak keşfetmeye çalışır. Bu, yaygın kullanılan dosya adları veya dizin adlarını tarayarak hedefteki potansiyel güvenlik zafiyetlerini bulmayı sağlar.

- Uzantı Filtreleme: DirBuster, belirli dosya uzantılarını filtreleyerek yalnızca belirli türdeki dosyaları taramak için kullanılabilir. Örneğin, sadece .php uzantılı dosyaları taramak gibi.

<a href="https://owasp.org/projects/" target="\_blank">Dirbuster</a>

Kaynak Kod: https://gitlab.com/kalilinux/packages/dirbuster

<hr>

# Airgeddon

Airgeddon, kablosuz ağ güvenliği testleri için tasarlanmış bir açık kaynaklı kablosuz ağ saldırı aracıdır. Airgeddon, bir arayüz üzerinden kolayca yönetilebilen ve farklı kablosuz güvenlik saldırıları gerçekleştiren bir kablosuz ağ güvenlik test çerçevesidir. Birçok farklı kablosuz saldırı tekniğini destekler ve basit bir kullanıcı arayüzü üzerinden bu saldırıları gerçekleştirmeyi kolaylaştırır.

## Airgeddon'ın temel özellikleri şunlardır:

- WEP, WPA ve WPA2 Saldırıları: Airgeddon, WEP, WPA ve WPA2 gibi farklı kablosuz güvenlik protokollerini hedef alarak kablosuz ağları test etmeye yönelik çeşitli saldırıları gerçekleştirebilir.

- Man-in-the-Middle Saldırıları: Airgeddon, kablosuz ağ üzerinde man-in-the-middle saldırıları yaparak ağ trafiğini izleme ve yönlendirme yeteneğine sahiptir.

- Güvenlik Zafiyeti Taramaları: Airgeddon, kablosuz ağlar üzerinde güvenlik açıkları ve zafiyetleri taramak için çeşitli teknikler kullanır.

- WPS Saldırıları: Airgeddon, WPS (Wi-Fi Protected Setup) güvenlik protokolünü hedef alarak kolayca şifre kırmayı deneyebilir.

<a href="https://github.com/v1s1t0r1sh3r3/airgeddon" target="\_blank">Airgeddon</a>

<hr>

# Steghide

Steghide, açık kaynaklı ve komut satırı tabanlı bir veri gizleme aracıdır. Steghide, bir medya dosyası (resim, ses veya video gibi) içine veri veya dosya gizlemek için kullanılır. Bu teknik, steganografi olarak bilinir ve verilerin görsel veya işitsel medya gibi diğer verilerin içine gizlenmesini sağlar.

## Steghide'in temel özellikleri şunlardır:

- Veri Gizleme: Steghide, bir kapak medya dosyası içine gizlemek istediğiniz verileri (metin veya dosyalar) gizlemenizi sağlar. Kapak dosya, genellikle görsel bir resim (JPEG, BMP, PNG) veya ses dosyası (WAV) olabilir.

- Şifreleme Desteği: Steghide, gizlenen verileri şifreleyerek ek güvenlik sağlar. Bu sayede gizlenen verilere erişim için bir şifre gereklidir.

- Parola Koruma: Steghide, gizlenen verilere erişimi sınırlandırmak için parola koruması eklemek için kullanılabilir.

- Farklı Veri Türleri: Steghide, metin dosyaları, resim dosyaları veya herhangi bir dosyayı bir kapak medya dosyasına gizlemek için kullanılabilir.

<a href="https://steghide.sourceforge.net/" target="\_blank">Steghide</a>

<hr>

# Parsero

Parsero, açık kaynaklı bir web uygulama güvenlik tarayıcısıdır. Bu araç, web uygulamalarını tarayarak güvenlik açıklarını ve zafiyetleri tespit etmek için kullanılır. Parsero, web sitelerini otomatik olarak tarar ve farklı güvenlik açıklarını ve zayıf noktaları belirlemek için çeşitli testler yapar.

## Parsero'nun temel özellikleri şunlardır:

- Güvenlik Açıkları Tarayıcı: Parsero, web sitelerini otomatik olarak tarayarak yaygın güvenlik açıklarını ve zayıf noktaları tespit eder. Bu açıklar arasında SQL enjeksiyonu, XSS (Cross-Site Scripting), dizin tarama, dosya yüklemesi ve daha fazlası yer alabilir.

- URL Tarayıcı: Parsero, belirtilen URL'leri veya bir alan adının altındaki tüm sayfaları tarayarak güvenlik açıklarını tespit eder.

- Otomatik Tarama: Parsero, web uygulamalarını otomatik olarak tarayarak güvenlik testlerini gerçekleştirir ve sonuçları raporlar.

- Basit ve Kullanıcı Dostu Arayüz: Parsero, kullanıcı dostu bir arayüze sahiptir ve kullanımı oldukça kolaydır.

<a href="https://github.com/behindthefirewalls/Parsero" target="\_blank">Parsero</a>

<hr>

# Metagoofil

Metagoofil, açık kaynaklı bir istihbarat toplama aracıdır (OSINT - Open Source Intelligence). Bu araç, belirli bir hedef alan adı veya IP adresi hakkında çeşitli metaveri ve belgeleri toplamak için kullanılır. Metagoofil, hedefle ilgili açık kaynaklardan gelen verileri toplamak ve analiz etmek amacıyla güvenlik uzmanları ve sızma test uzmanları tarafından kullanılır.

## Metagoofil'ün temel özellikleri şunlardır:

- Dosya İndirme: Metagoofil, belirtilen hedef alan adı veya IP adresi için çeşitli belge türlerini (örneğin, PDF, DOC, XLS) indirerek metaveri ve içerikleri analiz eder.

- Metaveri Analizi: Metagoofil, indirilen belgelerin metaverilerini (örneğin, yazar adı, oluşturma tarihi, değiştirme tarihi) analiz eder ve bu verileri raporlar.

- Görsel Analiz: Metagoofil, belgelerin içinde görsel medya dosyalarını taramak ve analiz etmek için kullanılabilir.

- Veri Sızdırma Tespiti: Metagoofil, belirli bir alan adıyla ilişkili belgelerde veri sızdırma durumlarını tespit etmeye yardımcı olabilir.

<a href="https://github.com/opsdisk/metagoofil" target="\_blank">Metagoofil</a>

<hr>

# Hping3

hping3, açık kaynaklı ve komut satırı tabanlı bir ağ test aracıdır. hping3, çeşitli ağ protokollerini test etmek, paketler göndermek ve almak, ağ performansını değerlendirmek ve ağ güvenliği testleri yapmak için kullanılır. hping3, TCP/IP ve diğer ağ protokollerini daha düşük seviyede manipüle etmek için kullanılabilir.

## hping3'ün temel özellikleri şunlardır:

- Paket Oluşturma ve Gönderme: hping3, özelleştirilmiş ağ paketleri oluşturabilir ve belirli hedeflere göndererek ağdaki tepkileri test edebilir.

- Paket Analizi: hping3, gönderilen veya alınan ağ paketlerini analiz ederek ağdaki durumu ve tepkileri inceleyebilir.

- DoS (Denial of Service) Saldırıları: hping3, DoS saldırılarına benzer saldırıları simüle edebilir ve ağın tepkisini inceleyerek ağ güvenliğini test edebilir.

- Port Tarama: hping3, belirli hedeflerdeki portların açık veya kapalı olduğunu taramak için kullanılabilir.

- Firewall Testleri: hping3, ağ güvenlik duvarlarını veya ağ filtrelerini test etmek için kullanılabilir.

<a href="http://www.hping.org/" target="\_blank">Hping3</a>

<hr>

# Commix

Commix, açık kaynaklı bir komut enjeksiyon test aracıdır. Bu araç, web uygulamalarında komut enjeksiyon zafiyetlerini tespit etmek ve bu zafiyetleri test etmek için kullanılır. Komut enjeksiyonu, web uygulamalarının dışardan veri girdisi alırken bu girdileri yetersiz şekilde işlemesi sonucu oluşan bir güvenlik açığıdır. Bu tür zafiyetler, siber saldırganların hedef sistemde komutları çalıştırmasına izin verir.

## Commix'in temel özellikleri şunlardır:

- Komut Enjeksiyon Testi: Commix, web uygulamalarında komut enjeksiyonu zafiyetlerini tespit etmek ve bu zafiyetleri test etmek için çeşitli teknikler kullanır.

- Farklı Komut Yürütme Yöntemleri: Commix, farklı komut yürütme yöntemlerini kullanarak komutları hedef web uygulamasında çalıştırmaya çalışır.

- Parametre Testi: Commix, hedef web uygulamasının parametrelerine komut enjekte ederek zafiyetleri tespit etmeye yardımcı olur.

- Otomatik ve El ile Test Modları: Commix, otomatik olarak komut enjeksiyon zafiyetlerini taramak veya el ile belirli parametreleri test etmek için kullanılabilir.

<a href="https://commixproject.com/" target="\_blank">commix</a>

<hr>

# CeWL (Custom Word List Generator)

Cewl (Custom Word List Generator), açık kaynaklı bir araçtır ve çeşitli kaynaklardan özelleştirilmiş kelime listeleri oluşturmak için kullanılır. Bu kelime listeleri, saldırılar sırasında parola kırma, saldırı sözlüğü oluşturma veya güvenlik testleri yapma gibi amaçlar için kullanılabilir.

## Cewl'ün temel özellikleri şunlardır:

- Kelime Listesi Oluşturma: Cewl, belirli bir web sitesi veya metin kaynağı üzerinden özelleştirilmiş kelime listeleri oluşturur. Bu, hedefin dilini, konusunu veya içeriğini dikkate alarak daha etkili kelime listeleri oluşturmayı sağlar.

- Web Sitelerini Tarama: Cewl, belirtilen bir web sitesini taramak ve web sitesindeki metni analiz ederek kelime listeleri oluşturmak için kullanılır.

- Filtreleme ve Temizleme: Cewl, oluşturulan kelime listelerini filtreleyebilir ve gereksiz veya istenmeyen kelimeleri temizleyebilir.

<a href="https://github.com/digininja/CeWL" target="\_blank">CeWL</a>

<hr>

# Assetfinder

Assetfinder, açık kaynaklı bir araçtır ve bir hedef alan adının altında bulunan alt alan adlarını ve altyapı bileşenlerini (varlık) keşfetmek için kullanılır. Bu tür varlıklar, sızma testleri sırasında veya güvenlik değerlendirmeleri yaparken hedef alan adının yüzeyini taramak için kullanılır.

## Assetfinder'ın temel özellikleri şunlardır:

- Alt Alan Adı Taraması: Assetfinder, belirtilen bir hedef alan adının altında bulunan alt alan adlarını tarar ve bu alt alan adlarını listeleyebilir.

- Altyapı Bileşenleri: Assetfinder, hedef alan adının altında bulunan IP adreslerini, web sunucularını, DNS sunucularını ve diğer altyapı bileşenlerini taramak için kullanılır.

- Aktif Varlıkları Bulma: Assetfinder, hedef alan adının altında aktif olarak bulunan varlıkları (örneğin, erişilebilir web siteleri) bulmak için kullanılabilir.

<a href="https://github.com/tomnomnom/assetfinder" target="\_blank">Assetfinder</a>

<hr>

# Subfinder

Subfinder, açık kaynaklı bir alt alan adı keşif aracıdır. Bu araç, belirli bir hedef alan adının altında bulunan alt alan adlarını taramak ve keşfetmek için kullanılır. Subfinder, alt alan adlarını taramak ve bulmak için birden fazla alt alan adı kaynağını kullanarak geniş bir alt alan adı keşfi sağlar.

## Subfinder'ın temel özellikleri şunlardır:

- Alt Alan Adı Taraması: Subfinder, belirtilen bir hedef alan adının altında bulunan alt alan adlarını taramak için farklı kaynaklardan yararlanır.

- Birden Fazla Kaynak Kullanımı: Subfinder, farklı alt alan adı veritabanlarını ve DNS kaynaklarını kullanarak alt alan adlarını keşfetmeye çalışır.

- Sonuçları Birleştirme: Subfinder, farklı kaynaklardan gelen alt alan adı sonuçlarını birleştirir ve kullanıcıya sunar.

- Alt Alan Adı Doğrulama: Subfinder, keşfedilen alt alan adlarını DNS sorguları yaparak doğrular.

<a href="https://github.com/projectdiscovery/subfinder" target="\_blank">Subfinder</a>

<hr>

# Recon-ng

Recon-ng, açık kaynaklı bir keşif ve istihbarat toplama aracıdır (OSINT - Open Source Intelligence). Bu araç, çeşitli kaynaklardan veri toplayarak hedef hakkında bilgi toplamak ve analiz etmek için kullanılır. Recon-ng, sosyal medya profilleri, alan adları, IP adresleri, e-posta adresleri ve diğer açık kaynak verileri üzerinden istihbarat toplamak için kullanılır.

## Recon-ng'nin temel özellikleri şunlardır:

- Kaynaklar ve Modüller: Recon-ng, çeşitli kaynaklardan (API'lar, veritabanları, halka açık veri kaynakları) veri toplamak için farklı modülleri içerir.

- API Entegrasyonu: Recon-ng, popüler sosyal medya platformları, alan adı kaynakları ve diğer veri sağlayıcılarıyla entegre olabilir.

- Otomatik ve El ile Veri Toplama: Recon-ng, veriyi otomatik olarak toplayabileceğiniz gibi el ile belirli hedefler veya kaynaklar üzerinde de veri toplayabilir.

- Sonuçları Analiz Etme: Recon-ng, toplanan veriyi analiz etmek ve hedef hakkında daha fazla bilgi çıkarmak için kullanılabilir.

<a href="https://github.com/lanmaster53/recon-ng" target="\_blank">Recon-ng</a>

<hr>

# GoldenEye

GoldenEye, açık kaynaklı bir yük testi aracıdır ve bir hedef web sitesine aşırı yükleme yaparak site performansını test etmek için kullanılır. Bu tür yük testleri, web sitesinin trafik yoğunluğuna dayanıklılığını ve tepki sürelerini değerlendirmek amacıyla yapılır.

## GoldenEye'nin temel özellikleri şunlardır:

- HTTP Flood Saldırıları: GoldenEye, hedef web sitesine HTTP flood saldırıları yaparak yüksek miktarda istek gönderir. Bu, hedef web sitesinin sunucu kaynaklarını tüketmeye ve performansını düşürmeye çalışır.

- Basit Kullanım: GoldenEye'nin kullanımı oldukça basittir ve komut satırından kolayca çalıştırılabilir.

- Özelleştirilebilir Parametreler: GoldenEye, saldırı parametrelerini özelleştirmenize izin verir. Bu sayede saldırının yoğunluğunu, hızını ve hedefleri ayarlayabilirsiniz.

- Doğrulama ve Analiz: GoldenEye, saldırı sonuçlarını analiz etmek ve hedef web sitesinin tepki sürelerini değerlendirmek için kullanılabilir.

<a href="https://github.com/jseidl/GoldenEye" target="\_blank">GoldenEye</a>

<hr>

# Fern-Wifi-Cracker

Fern Wifi Cracker, açık kaynaklı bir kablosuz ağ saldırı aracıdır. Bu araç, kablosuz ağlara yönelik güvenlik zafiyetlerini tespit etmek ve bu ağları güvenlik açısından değerlendirmek için kullanılır. Fern Wifi Cracker, sızma testleri sırasında kablosuz ağ güvenliği konusunda testler yapmak amacıyla kullanılabilir.

## Fern Wifi Cracker'ın temel özellikleri şunlardır:

- WEP, WPA, WPA2 Kırma: Fern Wifi Cracker, WEP, WPA ve WPA2 gibi yaygın kablosuz güvenlik protokollerini hedef alarak şifre kırma saldırıları gerçekleştirebilir.

- Otomatik ve El ile Saldırılar: Fern Wifi Cracker, şifre kırma saldırılarını otomatik olarak gerçekleştirebileceği gibi kullanıcı tarafından özelleştirilebilecek manuel saldırı seçenekleri de sunar.

- WPS Saldırıları: Fern Wifi Cracker, WPS (Wi-Fi Protected Setup) protokolünün zafiyetlerini kullanarak kablosuz ağları hedef alabilir.

- WPA/WPA2 El Sıkışma Saldırıları: Fern Wifi Cracker, WPA/WPA2 el sıkışma aşamalarını kaydedebilir ve ardından çeşitli yöntemlerle şifre kırma girişimlerinde bulunabilir.

<a href="https://github.com/savio-code/fern-wifi-cracker" target="\_blank">Fern-Wifi-Cracker</a>

<hr>

# Bettercap

Bettercap, açık kaynaklı bir ağ güvenliği aracıdır ve ağ saldırıları gerçekleştirmek, ağ trafiğini analiz etmek ve ağdaki güvenlik zafiyetlerini tespit etmek için kullanılır. Bettercap, özellikle kablosuz ağlarda ve Ethernet ağlarında çeşitli saldırılar yapmak ve ağ trafiğini izlemek için kullanılır.

## Bettercap'in temel özellikleri şunlardır:

- Ağ Saldırıları: Bettercap, ağdaki cihazlara yönelik çeşitli saldırılar gerçekleştirebilir. Örneğin, ARP zehirleme saldırıları, DHCP saldırıları, DNS zehirleme ve daha fazlasını gerçekleştirebilir.

- Ağ Trafiği Analizi: Bettercap, ağ trafiğini izleyebilir, analiz edebilir ve gelen veya giden verileri görüntüleyebilir.

- SSLstrip ve HSTS Bypass: Bettercap, SSL bağlantılarını izlemek ve SSLstrip gibi saldırıları gerçekleştirmek için kullanılabilir. Ayrıca, HSTS (HTTP Strict Transport Security) gibi güvenlik mekanizmalarını bypass etmeye yardımcı olabilir.

- Web Arayüzü: Bettercap, basit ve kullanıcı dostu bir web arayüzüne sahiptir, böylece kullanıcılar komut satırı kullanmadan aracı yönetebilirler.

<a href="https://www.bettercap.org/" target="\_blank">Bettercap</a>

<hr>

<a href="https://github.com/projectdiscovery/subfinder" target="\_blank">Subfinder</a>
<a href="https://github.com/projectdiscovery/subfinder" target="\_blank">Subfinder</a>
<a href="https://github.com/projectdiscovery/subfinder" target="\_blank">Subfinder</a>


# Performance

## Hardware resources

    Processor: AMD Ryzen 7 3750H with Radeon Vega Mobile Gfx   (8 CPUs), ~2.3GHz
    Available OS Memory: 15810MB RAM
    OS: 
    +) Windows 10 Pro 64-bit (10.0, Build 19042) (19041.vb_release.191206-1406)
    +) Kali linux 2021.1 amd64

## Computation Performance

### Plaintext: 

Harry Potter và Hòn đá Phù thủy (tiếng Anh: Harry Potter and the Philosophers Stone) là tác phẩm đầu tiên trong bộ truyện Harry Potter gồm 7 tập của nữ văn sĩ người Anh J. K. Rowling. Quyển sách đã được xuất bản ngày 30 tháng 6 năm 1997 bởi nhà bản Bloomsbury. Đây là một tập truyện quan trọng, bởi nó đặt nền tảng cho 6 tập tiếp theo. Nó giúp ta bước đầu khám phá thế giới Pháp thuật của Harry Potter, làm quen với các nhân vật chính, địa điểm, với một số thuật ngữ... Tập đầu tiên này đưa ra những câu hỏi chưa có câu trả lời, bằng những dấu hiệu cho những tình tiết trong các tập tiếp theo, tạo cho độc giả sự tò mò.

Authentication data: Nguyễn Phúc Chương

Tag size = 16

### Run 1000 times and take the average (ms)

|Scheme|	Mode|	Key length|	IV length|	Encryption  (Windows)|	Decryption (Windows)|	Encryption (Linux)|	Decryption (Linux)|
|--|------|-------|------|------|------|------|------|
|AES|	ECB|	128|	   |	0.0023|	0.0023|	0.0043|	0.0035|
|AES|	ECB|	192|	   |	0.0021|	0.0023|	0.0047|	0.0033|
|AES|	ECB|	256|	   |	0.0019|	0.0021|	0.0045|	0.0033|
|AES|	CBC|	128|	128|	0.0028|	0.0027|	0.0063|	0.0023|
|AES|	CBC|	192|	128|	0.0028|	0.0024|	0.0068|	0.0020|
|AES|	CBC|	256|	128|	0.0030|	0.0024|	0.0071|	0.0019|
|AES|	OFB|	128|	128|	0.0038|	0.0032|	0.0068|	0.0027|
|AES|	OFB|	192|	128|	0.0034|	0.0035|	0.0074|	0.0024|
|AES|	OFB|	256|	128|	0.0032|	0.0033|	0.0034|	0.0026|
|AES|	CFB|	128|	128|	0.0031|	0.0024|	0.0068|	0.0023|
|AES|	CFB|	192|	128|	0.0028|	0.0028|	0.0070|	0.0020|
|AES|	CFB|	256|	128|	0.0032|	0.0022|	0.0071|	0.0021|
|AES|	CTR|	128|	128|	0.0024|	0.0025|	0.0057|	0.0029|
|AES|	CTR|	192|	128|	0.0028|	0.0024|	0.0052|	0.0031|
|AES|	CTR|	256|	128|	0.0021|	0.0022|	0.0056|	0.0030|
|AES|	XTS|	256|	128|	0.0034|	0.0031|	0.0074|	0.0025|
|AES|	XTS|	384|	128|	0.0038|	0.0031|	0.0069|	0.0028|
|AES|	XTS|	512|	128|	0.0037|	0.0031|	0.0072|	0.0027|
|AES|	CCM|	128|	13 |	0.0029|	0.0052|	0.0068|	0.0039|
|AES|	CCM|	192|	13 |	0.0034|	0.0054|	0.0032|	0.0038|
|AES|	CCM|	256|	13 |	0.0032|	0.0055|	0.0075|	0.0039|
|AES|	GCM|	128|	20 |	0.0023|	0.0051|	0.0055|	0.0045|
|AES|	GCM|	192|	20 |	0.0024|	0.0048|	0.0060|	0.0039|
|AES|	GCM|	256|	20 |	0.0030|	0.0056|	0.0060|	0.0041|


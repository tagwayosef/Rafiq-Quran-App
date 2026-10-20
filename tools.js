// node tools.js admin|supervisor|participant email   |   node tools.js password email كلمة_جديدة
require("dotenv").config();const mysql=require("mysql2/promise"),bcrypt=require("bcryptjs");
(async()=>{const[c,e,v]=process.argv.slice(2);if(!c||!e){console.log("الاستخدام: node tools.js admin|supervisor|participant email  أو  node tools.js password email كلمة_جديدة");process.exit(1)}
const db=await mysql.createConnection({host:process.env.DB_HOST,user:process.env.DB_USER,password:process.env.DB_PASS,database:process.env.DB_NAME});let r;
if(["admin","supervisor","participant"].includes(c))r=await db.query("update users set role=? where email=?",[c,e.toLowerCase()]);
else if(c=="password"&&v&&v.length>=8)r=await db.query("update users set pass_hash=? where email=?",[await bcrypt.hash(v,10),e.toLowerCase()]);
else{console.log("أمر غير صالح (كلمة المرور 8 أحرف فأكثر)");process.exit(1)}
console.log(r[0].affectedRows?"تم":"لا يوجد مستخدم بهذا البريد");process.exit()})();

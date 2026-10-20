require("dotenv").config();
const express=require("express"),mysql=require("mysql2/promise"),bcrypt=require("bcryptjs"),jwt=require("jsonwebtoken"),multer=require("multer"),fs=require("fs"),path=require("path"),crypto=require("crypto");
const{DB_HOST,DB_USER,DB_PASS,DB_NAME,JWT_SECRET,PORT=3000}=process.env;
if(!JWT_SECRET||JWT_SECRET.length<24){console.error("ضع JWT_SECRET (24 حرفًا فأكثر) في ملف .env");process.exit(1)}
const db=mysql.createPool({host:DB_HOST,user:DB_USER,password:DB_PASS,database:DB_NAME,dateStrings:true,connectionLimit:10,charset:"utf8mb4"});
const Q=async(s,a=[])=>(await db.query(s,a))[0];
const DIR=path.resolve(process.env.AUDIO_DIR||path.join(__dirname,"audio"));fs.mkdirSync(DIR,{recursive:true});
const up=multer({storage:multer.diskStorage({destination:DIR,filename:(q,f,cb)=>{q.sid=crypto.randomUUID();cb(null,q.sid)}}),limits:{fileSize:10*1048576,files:1},fileFilter:(q,f,cb)=>cb(null,/^audio\/(webm|ogg|mp4|mpeg|wav|x-m4a)/.test(f.mimetype))});
const TYPES=["حفظ جديد","مراجعة","تثبيت"],STS=["pending","approved","rejected"],DT=/^\d{4}-\d{2}-\d{2}$/;
const bad=(m,c=400)=>{const e=new Error(m);e.status=c;throw e};
const H=fn=>(q,s)=>fn(q,s).catch(e=>{if(!e.status)console.error(e);s.status(e.status||500).json({error:e.status?e.message:"خطأ في الخادم"})});
const app=express();app.set("trust proxy",1);app.use(express.json({limit:"100kb"}));
app.use((q,s,n)=>{s.setHeader("X-Content-Type-Options","nosniff");s.setHeader("Referrer-Policy","no-referrer");n()});
const hits=new Map(),lim=(q,s,n)=>{const now=Date.now(),a=(hits.get(q.ip)||[]).filter(t=>now-t<9e5);if(a.length>=20)return s.status(429).json({error:"محاولات كثيرة، حاولي لاحقًا"});a.push(now);hits.set(q.ip,a);n()};
const auth=async(q,s,n)=>{try{const p=jwt.verify((q.headers.authorization||"").slice(7),JWT_SECRET),[u]=await Q("select id,name,role,hide_ranking from users where id=?",[p.id]);if(!u)throw 0;q.me=u;n()}catch(e){s.status(401).json({error:"سجّلي الدخول"})}};
const supOf=async(me,uid)=>me.role=="admin"||(me.role=="supervisor"&&(await Q("select 1 from group_members m join memorization_groups g on g.id=m.group_id where m.user_id=? and g.supervisor_id=? limit 1",[uid,me.id])).length>0);
const need=async(me,uid)=>{if(!uid||!await supOf(me,uid))bad("غير مصرح",403)};
const staff=me=>me.role!="participant";
const rangeOk=async(sr,f,t)=>{const[x]=await Q("select ayahs from surahs where id=?",[sr]);if(!x||!Number.isInteger(f)||!Number.isInteger(t)||f<1||t<f||t>x.ayahs)bad("نطاق الآيات غير صالح لهذه السورة")};
const tok=id=>jwt.sign({id},JWT_SECRET,{expiresIn:"7d"});
app.get("/api/health",(q,s)=>s.json({ok:1}));
app.post("/api/register",lim,H(async(q,s)=>{const n=String(q.body.name||"").replace(/[<>&"]/g,"").trim().slice(0,80),e=String(q.body.email||"").trim().toLowerCase(),p=String(q.body.password||"");
 if(!n||!/^\S+@\S+\.\S+$/.test(e)||p.length<8)bad("تحقق من الاسم والبريد وكلمة المرور (8 أحرف على الأقل)");
 if((await Q("select 1 from users where email=?",[e])).length)bad("البريد مسجّل مسبقًا",409);
 const id=crypto.randomUUID();await Q("insert into users(id,name,email,pass_hash)values(?,?,?,?)",[id,n,e,await bcrypt.hash(p,10)]);s.json({token:tok(id)})}));
app.post("/api/login",lim,H(async(q,s)=>{const[u]=await Q("select id,pass_hash from users where email=?",[String(q.body.email||"").trim().toLowerCase()]);
 if(!u||!await bcrypt.compare(String(q.body.password||""),u.pass_hash))bad("البريد أو كلمة المرور غير صحيحة",401);s.json({token:tok(u.id)})}));
app.get("/api/state",auth,H(async(q,s)=>{const me=q.me;let ids;
 if(me.role=="admin")ids=await Q("select id from users where role='participant'");
 else if(me.role=="supervisor")ids=await Q("select distinct m.user_id id from group_members m join memorization_groups g on g.id=m.group_id where g.supervisor_id=?",[me.id]);
 else ids=[{id:me.id},...await Q("select distinct b.user_id id from group_members a join group_members b on a.group_id=b.group_id join users u on u.id=b.user_id where a.user_id=? and b.user_id<>? and u.hide_ranking=0",[me.id,me.id])];
 ids=ids.map(x=>x.id);const IN=ids.length?ids:["-"],st=staff(me)?1:0;
 const users=await Q("select id,name,hide_ranking hide from users where id in (?)",[IN]),
 plans=await Q("select user_id userId,verses_per_day perDay,start_date startDate from memorization_plans where user_id in (?)",[IN]),
 records=await Q("select r.id,r.user_id userId,r.surah,r.from_ayah fromA,r.to_ayah toA,r.rec_date date,r.type,r.status,r.rating,r.notes,(select id from recitation_submissions where record_id=r.id limit 1) sid from memorization_records r where r.user_id in (?) and (? or r.user_id=? or r.status='approved')",[IN,st,me.id]),
 revisions=await Q("select id,user_id userId,surah,from_ayah fromA,to_ayah toA,note from revision_assignments where closed=0 and user_id in (?)",[IN]),
 groups=me.role=="admin"?await Q("select id,name from memorization_groups"):me.role=="supervisor"?await Q("select id,name from memorization_groups where supervisor_id=?",[me.id]):await Q("select g.id,g.name from memorization_groups g join group_members m on m.group_id=g.id where m.user_id=?",[me.id]),
 notifications=await Q("select title,body from notifications where user_id=? order by created_at desc limit 30",[me.id]);
 records.forEach(r=>{r.audio=r.sid&&(st||r.userId==me.id)?`/api/audio/${r.sid}?k=${jwt.sign({sid:r.sid,uid:me.id},JWT_SECRET,{expiresIn:"1h"})}`:null;delete r.sid});
 s.json({me:{id:me.id,name:me.name,role:me.role,hide:me.hide_ranking},users,plans,records,revisions,groups,notifications})}));
app.get("/api/audio/:sid",H(async(q,s)=>{let p;try{p=jwt.verify(String(q.query.k),JWT_SECRET)}catch(e){return s.status(401).end()}
 if(p.sid!==q.params.sid)return s.status(403).end();const[a]=await Q("select id,user_id,mime from recitation_submissions where id=?",[p.sid]),[me]=await Q("select id,role from users where id=?",[p.uid]);
 if(!a||!me||!(a.user_id==me.id||await supOf(me,a.user_id)))return s.status(403).end();
 s.setHeader("Content-Type",a.mime||"audio/webm");s.setHeader("Cache-Control","private, no-store");s.sendFile(path.join(DIR,a.id))}));
app.post("/api/submit",auth,up.single("audio"),H(async(q,s)=>{const me=q.me,b=q.body,sr=+b.surah,f=+b.from,t=+b.to,ty=b.type;
 try{if(me.role!="participant")bad("التسميع للمشاركات فقط");if(!q.file)bad("لم يصل ملف صوتي صالح");await rangeOk(sr,f,t);if(!TYPES.includes(ty))bad("نوع غير صالح");
  if((await Q("select 1 from memorization_records where user_id=? and surah=? and from_ayah=? and to_ayah=? and type=? and status<>'rejected'",[me.id,sr,f,t,ty])).length)bad("هذا التسميع مسجّل مسبقًا",409);
  const rid=crypto.randomUUID(),c=await db.getConnection();
  try{await c.beginTransaction();await c.query("insert into memorization_records(id,user_id,surah,from_ayah,to_ayah,type,status)values(?,?,?,?,?,?,'pending')",[rid,me.id,sr,f,t,ty]);
   await c.query("insert into recitation_submissions(id,record_id,user_id,size_bytes,duration_sec,mime)values(?,?,?,?,?,?)",[q.sid,rid,me.id,q.file.size,+b.duration||null,q.file.mimetype.split(";")[0]]);await c.commit()}
  catch(e){await c.rollback();throw e}finally{c.release()}
  s.json({ok:1})}catch(e){if(q.file)fs.unlink(q.file.path,()=>{});throw e}}));
app.post("/api/records",auth,H(async(q,s)=>{const b=q.body;await need(q.me,b.userId);await rangeOk(+b.surah,+b.from,+b.to);if(!TYPES.includes(b.type)||!STS.includes(b.status)||!DT.test(b.date))bad("بيانات غير صالحة");
 await Q("insert into memorization_records(id,user_id,surah,from_ayah,to_ayah,rec_date,type,status,rating)values(uuid(),?,?,?,?,?,?,?,?)",[b.userId,+b.surah,+b.from,+b.to,b.date,b.type,b.status,b.rating||null]);s.json({ok:1})}));
const getRec=async id=>{const[r]=await Q("select * from memorization_records where id=?",[id]);if(!r)bad("غير موجود",404);return r};
app.put("/api/records/:id",auth,H(async(q,s)=>{const r=await getRec(q.params.id),b=q.body;await need(q.me,r.user_id);await rangeOk(+b.surah,+b.from,+b.to);
 const rt=b.rating?+b.rating:null;if(!TYPES.includes(b.type)||!STS.includes(b.status)||!DT.test(b.date)||(rt!==null&&!(rt>=1&&rt<=5)))bad("بيانات غير صالحة");
 await Q("update memorization_records set surah=?,from_ayah=?,to_ayah=?,type=?,status=?,rec_date=?,rating=?,notes=? where id=?",[+b.surah,+b.from,+b.to,b.type,b.status,b.date,rt,String(b.notes||"").slice(0,500),r.id]);s.json({ok:1})}));
app.delete("/api/records/:id",auth,H(async(q,s)=>{const r=await getRec(q.params.id);if(!(await supOf(q.me,r.user_id))&&!(r.user_id==q.me.id&&r.status=="pending"))bad("غير مصرح",403);
 const subs=await Q("select id from recitation_submissions where record_id=?",[r.id]);await Q("delete from memorization_records where id=?",[r.id]);subs.forEach(x=>fs.unlink(path.join(DIR,x.id),()=>{}));s.json({ok:1})}));
app.post("/api/records/:id/evaluate",auth,H(async(q,s)=>{const r=await getRec(q.params.id);await need(q.me,r.user_id);const{status,rating,note}=q.body,n=String(note||"").slice(0,500);
 if(!["approved","rejected"].includes(status)||!(rating>=1&&rating<=5))bad("بيانات غير صالحة");const[sub]=await Q("select id from recitation_submissions where record_id=? limit 1",[r.id]);
 await Q("update memorization_records set status=?,rating=?,notes=? where id=?",[status,rating,n,r.id]);
 await Q("insert into recitation_evaluations(id,record_id,submission_id,supervisor_id,decision,rating,notes)values(uuid(),?,?,?,?,?,?)",[r.id,sub?sub.id:null,q.me.id,status,rating,n||null]);
 await Q("insert into notifications(id,user_id,title,body)values(uuid(),?,?,?)",[r.user_id,status=="approved"?"تم قبول تسميعك":"لم يُقبل تسميعك",n||null]);s.json({ok:1})}));
app.put("/api/plan",auth,H(async(q,s)=>{const b=q.body,p=Math.round(+b.perDay);await need(q.me,b.userId);if(!(p>=1)||!DT.test(b.startDate))bad("بيانات غير صالحة");
 await Q("insert into memorization_plans(id,user_id,verses_per_day,start_date,set_by)values(uuid(),?,?,?,?) on duplicate key update verses_per_day=values(verses_per_day),start_date=values(start_date),set_by=values(set_by)",[b.userId,p,b.startDate,q.me.id]);s.json({ok:1})}));
app.post("/api/revisions",auth,H(async(q,s)=>{const b=q.body;await need(q.me,b.userId);await rangeOk(+b.surah,+b.from,+b.to);
 await Q("insert into revision_assignments(id,user_id,surah,from_ayah,to_ayah,note,assigned_by)values(uuid(),?,?,?,?,?,?)",[b.userId,+b.surah,+b.from,+b.to,String(b.note||"").slice(0,500),q.me.id]);s.json({ok:1})}));
app.post("/api/revisions/:id/close",auth,H(async(q,s)=>{const[r]=await Q("select user_id from revision_assignments where id=?",[q.params.id]);if(!r)bad("غير موجود",404);await need(q.me,r.user_id);await Q("update revision_assignments set closed=1 where id=?",[q.params.id]);s.json({ok:1})}));
app.post("/api/groups",auth,H(async(q,s)=>{if(!staff(q.me))bad("غير مصرح",403);const n=String(q.body.name||"").replace(/[<>&"]/g,"").trim().slice(0,120);if(!n)bad("أدخلي اسم الحلقة");
 await Q("insert into memorization_groups(id,name,supervisor_id)values(uuid(),?,?)",[n,q.me.id]);s.json({ok:1})}));
app.post("/api/groups/:id/members",auth,H(async(q,s)=>{const[g]=await Q("select supervisor_id from memorization_groups where id=?",[q.params.id]);if(!g)bad("الحلقة غير موجودة",404);
 if(!(q.me.role=="admin"||g.supervisor_id==q.me.id))bad("غير مصرح",403);const[u]=await Q("select id from users where email=?",[String(q.body.email||"").trim().toLowerCase()]);if(!u)bad("لا يوجد مستخدم بهذا البريد",404);
 await Q("insert ignore into group_members(group_id,user_id)values(?,?)",[q.params.id,u.id]);s.json({ok:1})}));
app.delete("/api/members/:uid",auth,H(async(q,s)=>{if(!staff(q.me))bad("غير مصرح",403);
 if(q.me.role=="admin")await Q("delete from group_members where user_id=?",[q.params.uid]);else await Q("delete from group_members where user_id=? and group_id in (select id from memorization_groups where supervisor_id=?)",[q.params.uid,q.me.id]);s.json({ok:1})}));
app.put("/api/me",auth,H(async(q,s)=>{await Q("update users set hide_ranking=? where id=?",[q.body.hide?1:0,q.me.id]);s.json({ok:1})}));
app.use(express.static(path.join(__dirname,"public")));
app.use((e,q,s,n)=>s.status(400).json({error:e.code=="LIMIT_FILE_SIZE"?"حجم التسجيل يتجاوز 10 ميغابايت":"طلب غير صالح"}));
app.listen(PORT,()=>console.log("رفيق القرآن يعمل على المنفذ "+PORT));

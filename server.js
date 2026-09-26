const express = require("express");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const db = new Database("datemate.db");
db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, age INTEGER NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS profiles(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL, city TEXT NOT NULL, gender TEXT NOT NULL,
 bio TEXT DEFAULT '', hourly_rate INTEGER DEFAULT 0, active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS bookings(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL, profile_id INTEGER NOT NULL,
 booking_date TEXT NOT NULL, booking_time TEXT NOT NULL,
 duration INTEGER NOT NULL, status TEXT DEFAULT 'pending',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id),
 FOREIGN KEY(profile_id) REFERENCES profiles(id)
);
`);

const count = db.prepare("SELECT COUNT(*) c FROM profiles").get().c;
if (!count) {
  const add = db.prepare("INSERT INTO profiles(name,city,gender,bio,hourly_rate) VALUES(?,?,?,?,?)");
  add.run("Aisha","Kolkata","Female","Social companionship","1500");
  add.run("Riya","Durgapur","Female","Social companionship","1200");
  add.run("Arjun","Kolkata","Male","Social companionship","1400");
  add.run("Rahul","Asansol","Male","Social companionship","1100");
}

function auth(req,res,next){
  const h=req.headers.authorization||"";
  if(!h.startsWith("Bearer ")) return res.status(401).json({error:"Login required"});
  try { req.user=jwt.verify(h.slice(7),JWT_SECRET); next(); }
  catch { res.status(401).json({error:"Invalid or expired token"}); }
}

app.get("/api/profiles",(req,res)=>{
  const q=(req.query.q||"").trim(), gender=req.query.gender||"";
  let sql="SELECT id,name,city,gender,bio,hourly_rate FROM profiles WHERE active=1";
  const args=[];
  if(q){sql+=" AND (name LIKE ? OR city LIKE ?)"; args.push("%"+q+"%","%"+q+"%");}
  if(gender){sql+=" AND gender=?"; args.push(gender);}
  res.json(db.prepare(sql).all(...args));
});

app.post("/api/register",async(req,res)=>{
  const {name,email,password,age}=req.body;
  if(!name||!email||!password||Number(age)<18) return res.status(400).json({error:"All fields required; users must be 18+"});
  try{
    const hash=await bcrypt.hash(password,12);
    const r=db.prepare("INSERT INTO users(name,email,password_hash,age) VALUES(?,?,?,?)").run(name,email.toLowerCase(),hash,Number(age));
    const token=jwt.sign({id:r.lastInsertRowid,email:email.toLowerCase()},JWT_SECRET,{expiresIn:"7d"});
    res.json({token});
  }catch(e){res.status(409).json({error:"Email already registered"});}
});

app.post("/api/login",async(req,res)=>{
  const u=db.prepare("SELECT * FROM users WHERE email=?").get((req.body.email||"").toLowerCase());
  if(!u||!(await bcrypt.compare(req.body.password||"",u.password_hash))) return res.status(401).json({error:"Invalid email or password"});
  res.json({token:jwt.sign({id:u.id,email:u.email},JWT_SECRET,{expiresIn:"7d"})});
});

app.post("/api/bookings",auth,(req,res)=>{
  const {profile_id,booking_date,booking_time,duration}=req.body;
  if(!profile_id||!booking_date||!booking_time||!duration) return res.status(400).json({error:"Booking details required"});
  const p=db.prepare("SELECT id FROM profiles WHERE id=? AND active=1").get(profile_id);
  if(!p) return res.status(404).json({error:"Profile not found"});
  const r=db.prepare("INSERT INTO bookings(user_id,profile_id,booking_date,booking_time,duration) VALUES(?,?,?,?,?)")
    .run(req.user.id,profile_id,booking_date,booking_time,Number(duration));
  res.json({id:r.lastInsertRowid,status:"pending"});
});

app.get("/api/my-bookings",auth,(req,res)=>{
  res.json(db.prepare(`
    SELECT b.id,p.name,p.city,b.booking_date,b.booking_time,b.duration,b.status,b.created_at
    FROM bookings b JOIN profiles p ON p.id=b.profile_id
    WHERE b.user_id=? ORDER BY b.created_at DESC`).all(req.user.id));
});

app.get("/api/health",(req,res)=>res.json({ok:true,service:"DateMate API"}));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

app.listen(PORT,()=>console.log("DateMate running on port "+PORT));

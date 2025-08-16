require("dotenv").config() // Makes it so we can access .env file
const jwt = require("jsonwebtoken")//npm install jsonwebtoken dotenv
const bcrypt = require("bcrypt") //npm install bcrypt
const cookieParser = require("cookie-parser")//npm install cookie-parser
const express = require("express")//npm install express
const db = require("better-sqlite3")("scav.db") //npm install better-sqlite3
const body_parser = require("body-parser")
const crypto = require('crypto');
const nodemailer = require("nodemailer")
const axios = require("axios");
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const sharp = require('sharp');

db.pragma("journal_mode = WAL") //Makes it faster
const createTables = db.transaction(() => {
    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title STRING
        points INTEGER
        )
        `
    ).run()

    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER,
        team STRING,
        url STRING
        )
        `
    ).run()
})

createTables();

const app = express()
app.use(express.json())
app.set("view engine", "ejs")
app.set("views", path.join(__dirname, "views"));
app.use(express.static("public")) //Using public folder
app.use(cookieParser())
app.use(express.static('/public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(body_parser.json())


// Ensure upload folder exists
const uploadDir = path.join(__dirname, 'public', 'img');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer: store files in memory (we’ll process with Sharp)
const storage = multer.memoryStorage();
const upload = multer({ storage });


app.use(function (req, res, next) {

  let errors = [];

    try {
        const decoded = jwt.verify(req.cookies.scav, process.env.JWTSECRET)
        req.user = decoded
        req.admin = req.user.admin
        req.team = req.user.team
    } catch (err) {
        req.user = false
        req.admin = false;
        req.team = false;
    }

    res.locals.user = req.user;
    res.locals.admin = req.admin;
    res.locals.errors = errors;
    res.locals.team = req.team;

    next()
})

function mustBeLoggedIn(req, res, next){
    if(req.user) {
        return next()
    }
    else
    {
        return res.redirect("/")
    }
}

function mustBeAdmin(req, res, next){
    if(req.admin) {
        return next()
    }
    else
    {
        return res.redirect("/")
    }
}

app.get("/", (req,res) => {
    const targets = db.prepare("SELECT * FROM targets").all();

    let uploads = null;

    if(res.locals.team){
    uploads = db.prepare("SELECT * FROM uploads WHERE team = ?").all(res.locals.team)}

    let maxPoints = 0;

    targets.forEach(target => {
        maxPoints += target.points;
    })

    return res.render("index", {targets, uploads, maxPoints})
})

app.get("/upload/:team/:target", mustBeLoggedIn, (req,res) => {
    const target = db.prepare("SELECT * FROM targets WHERE id = ?").get(req.params.target)

    return res.render("upload", {targetid: req.params.target, target})
})


app.get("/login", (req,res) => {
    if(req.user)
        return res.redirect("/")

    return res.render("login")
})

app.post("/login", (req,res) => {
    if(req.user)
        return res.redirect("/")

    const password = req.body.password;

    let errors = [];
    let loggedIn = false;
    let admin = false;

    if(password=="AdminAdmin"){
        loggedIn = true;
        team="admin";
        admin = true;
    }

    if(password == "greengiant"){
        loggedIn = true;
        team = "green";
    }

    if(password == "yellowjacket"){
        loggedIn = true;
        team = "yellow";
    }

    if(password == "bluemoon"){
        loggedIn = true;
        team = "blue";
    }

    if(password == "redrover"){
        loggedIn = true;
        team = "red";
    }

    if(password == "norhyme"){
        loggedIn = true;
        team = "orange";
    }



    if(!loggedIn)
        errors.push("invalid password")

    if(errors.length > 0){
        return res.render("login", {errors})
    }

    const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + (60*60*24*3), team: team, admin: admin}, process.env.JWTSECRET) //Creating a token for logging in
          
          res.cookie("scav",ourTokenValue, {
              httpOnly: true,
              secure: true,
              sameSite: "Lax",
              maxAge: 1000 * 60 * 60 * 24
          }) //name, string to remember,

    return res.redirect("/")
})

app.get("/edit-prompts", mustBeAdmin, (req,res) => {
    const prompts = db.prepare("SELECT * FROM targets").all()
    return res.render("edit-prompts", {prompts})
})

app.post("/add-prompt", mustBeAdmin, (req,res) => {
    const name = req.body.prompt;
    const points = req.body.points;

    db.prepare("INSERT INTO targets (title, points) VALUES (?,?)").run(name,points)

    return res.redirect("/edit-prompts")
})

app.get("/delete-prompt/:id", mustBeAdmin, (req,res) => {
    db.prepare("DELETE FROM targets WHERE id = ?").run(req.params.id);

    return res.redirect("/edit-prompts")
})

app.get("/logout", mustBeLoggedIn, (req,res) => {
    res.clearCookie("scav")

    return res.redirect("/")
})

// Upload endpoint
app.post('/upload/:team/:targetid', mustBeLoggedIn, upload.single('file'), async (req, res) => {
    const { team, targetid } = req.params;

    if (!req.file) {
        return res.status(400).send('No file uploaded');
    }

    try {
        // Look for existing entry
        const existing = db.prepare(
            `SELECT * FROM uploads WHERE team = ? AND target_id = ?`
        ).get(team, targetid);

        if (existing) {
            // Delete old file if exists
            const oldPath = path.join(__dirname, 'public', existing.url);
            if (fs.existsSync(oldPath)) {
                fs.unlinkSync(oldPath);
            }

            // Remove DB entry
            db.prepare(`DELETE FROM uploads WHERE team = ? AND target_id = ?`)
              .run(team, targetid);
        }

        // Create unique filename
        const filename = `${team}_${targetid}_${Date.now()}.webp`;
        const outPath = path.join(uploadDir, filename);

        // Process image: resize to max 1080px (long side), auto-orient, convert to webp
        await sharp(req.file.buffer)
            .rotate() // fix iPhone orientation
            .resize({ width: 1080, height: 1080, fit: 'inside' })
            .webp({ quality: 80 })
            .toFile(outPath);

        // Insert into DB
        const url = `/img/${filename}`;
        db.prepare(
            `INSERT INTO uploads (target_id, team, url) VALUES (?, ?, ?)`
        ).run(targetid, team, url);

        // Redirect back
        res.redirect('/');
    } catch (err) {
        console.error(err);
        res.status(500).send('Upload failed');
    }
});

app.get("/clear", mustBeAdmin, (req, res) => {
    const uploadDir = path.join(__dirname, 'public', 'img');

    try {
        // Delete all files in /public/img
        if (fs.existsSync(uploadDir)) {
            fs.readdirSync(uploadDir).forEach(file => {
                const filePath = path.join(uploadDir, file);
                if (fs.lstatSync(filePath).isFile()) {
                    fs.unlinkSync(filePath);
                }
            });
        }

        // Clear all records from uploads table
        db.prepare(`DELETE FROM uploads`).run();

        // Reset autoincrement counter if you want clean IDs
        db.prepare(`DELETE FROM sqlite_sequence WHERE name='uploads'`).run();

        return res.redirect("/");
    } catch (err) {
        console.error("Error clearing uploads:", err);
        return res.status(500).send("Failed to clear uploads");
    }
});

app.get("/slideshow", (req, res) => {
    const rows = db.prepare(`
        SELECT 
            t.id as target_id,
            t.title,
            t.points,
            u.team,
            u.url
        FROM targets t
        JOIN uploads u
        ON t.id = u.target_id
        WHERE u.url IS NOT NULL
        ORDER BY t.id, u.team
    `).all();

    // Calculate team scores
    const scores = db.prepare(`
        SELECT u.team, SUM(t.points) as totalPoints
        FROM uploads u
        JOIN targets t
        ON u.target_id = t.id
        WHERE u.url IS NOT NULL
        GROUP BY u.team
        ORDER BY totalPoints DESC
        LIMIT 1
    `).get();

    const winner = {
        team: scores.team,
        points: scores.totalPoints,
        // If you want to show their last upload’s picture:
        url: db.prepare(`SELECT url FROM uploads WHERE team = ? ORDER BY id DESC LIMIT 1`).get(scores.team)?.url
    };

    res.render("slideshow", { rows, winner });
});


app.listen(8025)
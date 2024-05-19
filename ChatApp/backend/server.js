import path from "path";
import express from "express";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.routes.js";
import messageRoutes from "./routes/message.routes.js";
import userRoutes from "./routes/user.routes.js";
import connectToMongoDB from "./db/connetToMongoDB.js";
import { app, server } from "./socket/socket.js";
import cookieParser from "cookie-parser";
import cors from 'cors';
import helmet from 'helmet';
import csurf from 'csurf';

// HTTP security headers
app.use(helmet());
// Custom Helmet Configuration
app.use(helmet.frameguard({ action: 'deny' })); // Prevent clickjacking
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"], // Add your trusted script sources
    objectSrc: ["'none'"], // Prevent embedding objects
    upgradeInsecureRequests: [],
  },
}));
app.use(helmet.referrerPolicy({ policy: 'no-referrer' })); // Control the information sent in the Referer header

// Manual Expect-CT header configuration
app.use((req, res, next) => {
  res.setHeader('Expect-CT', 'max-age=86400, enforce');
  next();
});

app.use(helmet.dnsPrefetchControl({ allow: false }));
app.use(helmet.hidePoweredBy());
app.use(helmet.hsts({
  maxAge: 31536000, // 1 year
  includeSubDomains: true,
  preload: true
}));

// Limit repeated requests to public APIs and/or endpoints
import rateLimit from 'express-rate-limit';

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

app.use('/api/', limiter);

// CORS Protection
const corsOptions = {
  origin: 'http://localhost:3000', 
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true,
};

app.use(cors(corsOptions));

dotenv.config();

const __dirname = path.resolve();
const PORT = process.env.PORT || 5000;

app.use(express.json());
app.use(cookieParser());

const csrfProtection = csurf({ cookie: true });
app.use(csrfProtection);

app.use("/api/auth", authRoutes);
app.use("/api/messages", messageRoutes);
app.use("/api/users", userRoutes);

app.use(express.static(path.join(__dirname, "/frontend/dist")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "dist", "index.html"));
});


server.listen(PORT, () => {
	connectToMongoDB();
	console.log(`Server Running on port ${PORT}`);
});

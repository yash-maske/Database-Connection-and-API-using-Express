import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import connectDB from './config/connectdb.js';
import userRoutes from './routes/userRoutes.js'

const DATABASE_URL = process.env.DATABASE_URI;  // Fixed typo
const port = process.env.PORT || 8000;         // Ensure default value if PORT is missing

const app = express();
app.use(cors());
app.use(express.json());
app.use("/api/user",userRoutes);


connectDB(DATABASE_URL);

app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`); // Fixed 'locahost' typo
});

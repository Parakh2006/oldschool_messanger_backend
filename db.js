const mongoose = require("mongoose");

async function connectDB() {
  try {
    const uri = process.env.MONGO_URI;

    if (!uri) {
      throw new Error("MONGO_URI is missing in environment variables");
    }

    // FORCE the database name here (this fixes the 'test' DB problem)
    await mongoose.connect(uri, {
      dbName: "galiyoon",
    });

    console.log("✅ MongoDB connected");
    console.log("✅ Using database:", mongoose.connection.name);
  } catch (err) {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  }
}

module.exports = connectDB;

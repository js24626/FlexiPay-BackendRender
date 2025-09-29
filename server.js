// server.js
import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { Low } from 'lowdb'
import { JSONFile } from 'lowdb/node'
import { nanoid } from 'nanoid'

dotenv.config()
const app = express()
app.use(cors())
app.use(express.json())

// lowdb setup (file: db.json) — provide default data to avoid missing default data error
const adapter = new JSONFile('./db.json')
const defaultData = { users: [], agents: [], agentAmounts: [] }

// pass defaultData as second arg so lowdb won't throw on newer versions
const db = new Low(adapter, defaultData)

// read and ensure data exists
await db.read()
if (!db.data) {
  db.data = defaultData
  await db.write()
}

// Ensure all arrays exist
if (!db.data.agents) {
  db.data.agents = []
  await db.write()
}

if (!db.data.agentAmounts) {
  db.data.agentAmounts = []
  await db.write()
}

// create initial admin if env vars provided (optional)
if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
  const existing = db.data.users.find(u => u.email === process.env.ADMIN_EMAIL)
  if (!existing) {
    const hashed = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10)
    const admin = {
      id: nanoid(),
      email: process.env.ADMIN_EMAIL,
      password: hashed,
      role: 'admin',
      full_name: 'Admin',
      created_at: new Date().toISOString()
    }
    db.data.users.push(admin)
    await db.write()
    console.log('Admin created:', process.env.ADMIN_EMAIL)
  }
}

const JWT_SECRET = process.env.JWT_SECRET || 'please_change_this'

// helpers
function createToken(user) {
  return jwt.sign({ id: user.id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '7d' })
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' })
  const token = auth.split(' ')[1]
  try {
    const payload = jwt.verify(token, JWT_SECRET)
    req.user = payload
    next()
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' })
  }
}

function adminMiddleware(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Forbidden' })
  next()
}

app.get("/",(req,res)=>{
  res.send("Server is working ");
})

// ADMIN LOGIN
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' })
  await db.read()
  const user = db.data.users.find(u => u.email === email)
  if (!user) return res.status(400).json({ error: 'Invalid credentials' })
  const ok = await bcrypt.compare(password, user.password)
  if (!ok) return res.status(400).json({ error: 'Invalid credentials' })
  const token = createToken(user)
  res.json({ token, user: { id: user.id, email: user.email, role: user.role, full_name: user.full_name } })
})

// AGENT LOGIN
app.post('/auth/agent-login', async (req, res) => {
  const { username, password } = req.body
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' })
  
  await db.read()
  const agent = db.data.agents.find(a => a.username.toLowerCase() === username.toLowerCase())
  if (!agent) return res.status(400).json({ error: 'Invalid credentials' })
  
  const ok = await bcrypt.compare(password, agent.password)
  if (!ok) return res.status(400).json({ error: 'Invalid credentials' })
  
  const token = createToken({ id: agent.id, role: 'agent', email: agent.email })
  res.json({ 
    token, 
    user: { 
      id: agent.id, 
      username: agent.username,
      email: agent.email, 
      role: 'agent' 
    } 
  })
})

// AGENTS CRUD - Admin only
// GET all agents
app.get('/agents', authMiddleware, adminMiddleware, async (req, res) => {
  await db.read()
  const agents = db.data.agents.map(a => ({ 
    id: a.id, 
    username: a.username, 
    email: a.email, 
    created_at: a.created_at 
  }))
  res.json(agents)
})

// CREATE agent
app.post('/agents', authMiddleware, adminMiddleware, async (req, res) => {
  const { username, email, password } = req.body
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email and password required' })
  }
  
  await db.read()
  
  // Check if username already exists
  const existingAgent = db.data.agents.find(a => a.username.toLowerCase() === username.toLowerCase())
  if (existingAgent) {
    return res.status(400).json({ error: 'Username already exists' })
  }
  
  // Check if email already exists
  const existingEmail = db.data.agents.find(a => a.email.toLowerCase() === email.toLowerCase())
  if (existingEmail) {
    return res.status(400).json({ error: 'Email already exists' })
  }
  
  const hashedPassword = await bcrypt.hash(password, 10)
  const agent = {
    id: nanoid(),
    username,
    email,
    password: hashedPassword,
    created_at: new Date().toISOString()
  }
  
  db.data.agents.push(agent)
  await db.write()
  
  // Return agent without password
  res.json({ 
    id: agent.id, 
    username: agent.username, 
    email: agent.email, 
    created_at: agent.created_at 
  })
})

// DELETE agent
app.delete('/agents/:id', authMiddleware, adminMiddleware, async (req, res) => {
  await db.read()
  const idx = db.data.agents.findIndex(a => a.id === req.params.id)
  if (idx === -1) return res.status(404).json({ error: 'Agent not found' })
  
  db.data.agents.splice(idx, 1)
  await db.write()
  res.json({ success: true })
})

// AGENT AMOUNTS CRUD
// GET all agent amounts (admin only)
app.get('/agent-amounts', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    await db.read()
    res.json(db.data.agentAmounts || [])
  } catch (error) {
    console.error('Error loading agent amounts:', error)
    res.status(500).json({ error: 'Failed to load agent amounts' })
  }
})

// GET agent's own amounts (agent only)
app.get('/agent-amounts/my-amounts', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'agent') {
      return res.status(403).json({ error: 'Only agents can access their own amounts' })
    }

    await db.read()
    
    // Find agent by ID
    const agent = db.data.agents.find(a => a.id === req.user.id)
    if (!agent) {
      return res.status(404).json({ error: 'Agent not found' })
    }

    // Filter amounts by agent username
    const myAmounts = (db.data.agentAmounts || []).filter(
      amount => amount.createdBy === agent.username
    )
    
    res.json(myAmounts)
  } catch (error) {
    console.error('Error loading agent amounts:', error)
    res.status(500).json({ error: 'Failed to load agent amounts' })
  }
})

// CREATE agent amount (agents can create their own)
app.post('/agent-amounts', authMiddleware, async (req, res) => {
  try {
    const { amount, date, username } = req.body
    
    if (!amount || !date) {
      return res.status(400).json({ error: 'Amount and date are required' })
    }
    
    await db.read()
    
    let createdByUsername = username
    
    // For agents, verify they can only create amounts for themselves
    if (req.user.role === 'agent') {
      const agent = db.data.agents.find(a => a.id === req.user.id)
      if (!agent) {
        return res.status(403).json({ error: 'Agent not found' })
      }
      createdByUsername = agent.username
    }
    
    const agentAmount = {
      id: nanoid(),
      amount: parseFloat(amount),
      date,
      username: createdByUsername,
      createdBy: createdByUsername,
      createdAt: new Date().toISOString(),
      
    }
    
    if (!db.data.agentAmounts) {
      db.data.agentAmounts = []
    }
    
    db.data.agentAmounts.push(agentAmount)
    await db.write()
    
    res.json(agentAmount)
  } catch (error) {
    console.error('Error creating agent amount:', error)
    res.status(500).json({ error: 'Failed to create agent amount' })
  }
})

// DELETE agent amount (admin only)
app.delete('/agent-amounts/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    await db.read()
    const idx = db.data.agentAmounts.findIndex(a => a.id === req.params.id)
    if (idx === -1) {
      return res.status(404).json({ error: 'Agent amount not found' })
    }
    
    db.data.agentAmounts.splice(idx, 1)
    await db.write()
    res.json({ success: true })
  } catch (error) {
    console.error('Error deleting agent amount:', error)
    res.status(500).json({ error: 'Failed to delete agent amount' })
  }
})

// ADMIN: list users (no passwords)
app.get('/users', authMiddleware, adminMiddleware, async (req, res) => {
  await db.read()
  const users = db.data.users.map(u => ({ id: u.id, email: u.email, role: u.role, full_name: u.full_name, created_at: u.created_at }))
  res.json(users)
})

const port = process.env.PORT || 5000
app.listen(port, () => console.log(`FlexyPay backend running on http://localhost:${port}`))
export default app;
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db, User, Project, Task } = require('./database/setup');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

function requireManager(req, res, next) {
    if (req.user.role === 'manager' || req.user.role === 'admin') {
        return next();
    }
    return res.status(403).json({ error: 'Manager access required' });
}

function requireAdmin(req, res, next) {
    if (req.user.role === 'admin') {
        return next();
    }
    return res.status(403).json({ error: 'Admin access required' });
}

app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role = 'employee' } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Missing fields' });
        }

        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({
            name,
            email,
            password: hashedPassword,
            role
        });

        const token = jwt.sign(
            {
                id: newUser.id,
                name: newUser.name,
                email: newUser.email,
                role: newUser.role
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
                id: newUser.id,
                name: newUser.name,
                email: newUser.email,
                role: newUser.role
            }
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ where: { email } });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        res.status(500).json({ error: 'Failed to login' });
    }
});

app.post('/api/logout', (req, res) => {
    res.json({ message: 'Logout successful (client removes token)' });
});

app.get('/api/users/profile', requireAuth, async (req, res) => {
    const user = await User.findByPk(req.user.id, {
        attributes: ['id', 'name', 'email', 'role']
    });
    res.json(user);
});

app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
    const users = await User.findAll({
        attributes: ['id', 'name', 'email', 'role']
    });
    res.json(users);
});

app.get('/api/projects', requireAuth, async (req, res) => {
    const projects = await Project.findAll({
        include: [{ model: User, as: 'manager', attributes: ['id', 'name', 'email'] }]
    });
    res.json(projects);
});

app.get('/api/projects/:id', requireAuth, async (req, res) => {
    const project = await Project.findByPk(req.params.id, {
        include: [
            { model: User, as: 'manager', attributes: ['id', 'name', 'email'] },
            {
                model: Task,
                include: [{ model: User, as: 'assignedUser', attributes: ['id', 'name', 'email'] }]
            }
        ]
    });

    if (!project) return res.status(404).json({ error: 'Not found' });

    res.json(project);
});

app.post('/api/projects', requireAuth, requireManager, async (req, res) => {
    const project = await Project.create({
        name: req.body.name,
        description: req.body.description,
        managerId: req.user.id
    });

    res.json(project);
});

app.put('/api/projects/:id', requireAuth, requireManager, async (req, res) => {
    await Project.update(req.body, { where: { id: req.params.id } });
    res.json({ message: 'Updated' });
});

app.post('/api/projects/:id/tasks', requireAuth, requireManager, async (req, res) => {
    const task = await Task.create({
        title: req.body.title,
        description: req.body.description,
        projectId: req.params.id,
        assignedUserId: req.body.assignedUserId,
        status: 'pending'
    });

    res.json(task);
});

app.delete('/api/tasks/:id', requireAuth, requireManager, async (req, res) => {
    await Task.destroy({ where: { id: req.params.id } });
    res.json({ message: 'Deleted' });
});

app.get('/api/projects/:id/tasks', requireAuth, async (req, res) => {
    const tasks = await Task.findAll({
        where: { projectId: req.params.id },
        include: [{ model: User, as: 'assignedUser', attributes: ['id', 'name', 'email'] }]
    });

    res.json(tasks);
});

app.put('/api/tasks/:id', requireAuth, async (req, res) => {
    await Task.update(req.body, { where: { id: req.params.id } });
    res.json({ message: 'Updated' });
});

app.delete('/api/projects/:id', requireAuth, requireAdmin, async (req, res) => {
    await Project.destroy({ where: { id: req.params.id } });
    res.json({ message: 'Deleted' });
});

//start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
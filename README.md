# 🎓 ATMS – Academic Task Management System

ATMS (Academic Task Management System) is a role-based Django web application designed to manage academic projects, teams, and tasks across multiple campuses, schools, and departments.

---

## 📌 Overview

ATMS enables structured academic workflow management with strict role-based visibility control:

- 🏫 Coordinator → Campus-level access
- 🏢 HOD → School-level access
- 👨‍🏫 Staff → Department-level access
- 👩‍🎓 Student → Assigned task access

The system includes project management, team management, backlog view, Kanban board, task tracking, and Google authentication support.

---

## ✨ Features

### 🔐 Authentication
- Django Authentication
- Google OAuth Login (django-allauth)
- Role-based authorization

### 📁 Project Management
- Create and manage projects
- Auto project status (Upcoming / Ongoing / Completed)
- Department-based project visibility

### 👥 Team Management
- Create teams under projects
- Assign team heads
- Auto-prefix team name using project keyword
- Role-based team visibility

### 📋 Task Management
- Backlog view
- Kanban board view
- Task assignment
- Priority filtering
- Team filtering
- Subtask tracking with completion percentage
- Overdue detection

### 🖥️ Kanban Board
- To Do
- In Progress
- In Review
- Done
- Fullscreen mode support

---

## 🏗️ Tech Stack

- Python 3.12+ (Recommended)
- Django 4.x
- SQLite (default DB)
- django-allauth (Google OAuth)
- Bootstrap / Custom CSS
- JavaScript (Board interactions)

---

## ⚙️ Installation Guide

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/MangeshKokare/ATMS-repo.git
cd ATMS-repo

# VcLogin v5.1

Modern authentication system for Vietcong 1 Dedicated Servers.

VcLogin is a DLL-based authentication system designed for Vietcong 1 Dedicated Servers. The plugin injects directly into the server process and extends it with a full account system. Its main purpose is to protect player identities by binding nicknames to secure accounts, preventing impersonation, nickname theft, and duplicate-name abuse. No client-side modifications are required.

## Overview

VcLogin introduces a full account-based authentication layer into the Vietcong 1 dedicated server. Players are no longer identified only by nicknames, but by protected accounts with passwords, recovery codes and optional auto-login. The system runs entirely server-side as a DLL injection.

## Features

### Account System
Players can register and manage accounts directly in-game using commands:

/register <password> – create account  
/login <password> – authenticate account  
/passwd <new_password> – change password  
/autologin – toggle IP-based auto login  
/recovery <code> – recover account  
/info – server info  
/help – command list  
/about – plugin info  
/disconnect - disconnects you from server

Accounts are stored in an encrypted database and permanently linked to nicknames.

### Duplicate Nickname Protection
The system prevents multiple players from using the same nickname. If a duplicate is detected, unauthorized users are blocked and the original account owner retains full control over the name.

### Auto Login
Accounts can be linked to IP addresses for automatic authentication on future connections. This removes the need to repeatedly enter passwords while still keeping security intact.

### Password Recovery
Each account has a unique recovery code. If a password is lost, the account can be restored using this code without administrator intervention. A new recovery code is generated after every password change.

### Login Protection
The system includes brute-force protection, configurable login attempt limits, login timeout, and automatic kick for failed authentication attempts.

### Chat Protection
Chat spam is limited using a configurable cooldown system to prevent abuse.

### Account Security
Passwords are hashed, stored in encrypted form, and protected against direct access. Accounts can also be locked and tracked for security purposes.

## Guest Mode

VcLogin includes Guest Mode for public servers. When enabled, unregistered players can join and play immediately without creating an account. Registered players are still required to log in to access their protected identity. This allows casual players to join freely while maintaining full protection for registered users.

Example:  
Registered player "John" must log in, while unregistered player "Guest123" can play immediately.

## Server Console Commands

These commands are executed in the dedicated server console and not in-game chat.

guestmode 1 – enables guest mode  
guestmode 0 – disables guest mode  

spawndelay <0-30> – sets spawn delay for guest players in seconds (0 = no delay, 30 = maximum delay)

## Configuration

The system is configured via vclogin.ini. It controls database paths, password rules, guest mode behavior, chat cooldown and other server settings.

Example configuration:

database_file = players.db  
min_password_length = 4  
max_password_length = 32  
max_password_tries_per_connection = 3  
chat_cooldown_time = 2  
guest_mode = 1  
guest_mode_join_spawn_delay = 10  
custom_message = Welcome to our server! ; If you liked this tool, share it.

## Generated Files

players.db – encrypted account database  
autologin.dat – IP binding data  
admins.ini – administrator list  
vclogin.key – player's db encryption key  

## Security

VcLogin uses password hashing, encrypted storage, duplicate nickname prevention, brute-force protection, login timeout handling, recovery system and IP-based auto-login to secure all accounts.

## Installation

Copy VcLogin.dll into the server directory, configure vclogin.ini, inject or load the DLL into the dedicated server process and restart the server.

## Why VcLogin

Classic Vietcong servers rely only on nicknames, which leads to nickname theft, impersonation, admin abuse, identity confusion and duplicate names. VcLogin fixes this by turning every nickname into a protected account bound to a password and recovery system.

## License

This project is provided as-is for use on Vietcong 1 servers.

You are allowed to use this software in its original form for server operation and administration purposes.

You are NOT allowed to:
- modify the source or binaries and redistribute them as your own
- rebrand or rename the project
- remove author attribution
- publish altered versions under a different name

All rights reserved by the author.

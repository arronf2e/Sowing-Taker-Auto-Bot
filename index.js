require('dotenv').config();
const axios = require('axios');
const { ethers } = require('ethers');
const blessed = require('blessed');
const colors = require('colors');
const fs = require('fs');
const { HttpsProxyAgent } = require('https-proxy-agent');

const API_BASE_URL = 'https://sowing-api.taker.xyz';
const HEADERS = {
    'accept': 'application/json, text/plain, */*',
    'accept-language': 'en-US,en;q=0.9',
    'content-type': 'application/json',
    'sec-ch-ua': '"Microsoft Edge";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'Referer': 'https://sowing.taker.xyz/',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
};

const proxies = fs.existsSync('proxies.txt')
    ? fs.readFileSync('proxies.txt', 'utf-8')
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'))
    : [];
if (proxies.length === 0) {
    console.warn('No proxies found in proxies.txt. Running without proxies.');
}

const wallets = [];
for (let i = 1; ; i++) {
    const key = process.env[`PRIVATE_KEY_${i}`];
    if (!key) break;
    try {
        const wallet = new ethers.Wallet(key);
        wallets.push({
            privateKey: key,
            address: wallet.address,
            proxy: proxies.length > 0 ? proxies[Math.floor(Math.random() * proxies.length)] : null,
        });
    } catch (error) {
        console.error(`Invalid PRIVATE_KEY_${i}: ${error.message}`);
    }
}
if (wallets.length === 0) {
    throw new Error('No valid private keys found in .env file');
}

function logMessage(message, type = 'info', walletAddress = '') {
    const timestamp = new Date().toLocaleTimeString();
    const prefix = walletAddress ? `[${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}] ` : '';
    let coloredMessage;
    switch (type) {
        case 'error':
            coloredMessage = colors.red(`[${timestamp}] ${prefix}${message}`);
            break;
        case 'success':
            coloredMessage = colors.green(`[${timestamp}] ${prefix}${message}`);
            break;
        case 'warning':
            coloredMessage = colors.yellow(`[${timestamp}] ${prefix}${message}`);
            break;
        default:
            coloredMessage = colors.white(`[${timestamp}] ${prefix}${message}`);
    }
    console.log(coloredMessage);
}

let currentWalletIndex = 0;
const tokens = {};

function normalizeProxy(proxy) {
    if (!proxy) return null;
    if (!proxy.startsWith('http://') && !proxy.startsWith('https://')) {
        proxy = `http://${proxy}`;
    }
    return proxy;
}

async function apiRequest(url, method = 'GET', data = null, authToken = null, proxy = null) {
    const config = {
        method,
        url,
        headers: { ...HEADERS },
    };
    if (data) config.data = data;
    if (authToken) config.headers['authorization'] = `Bearer ${authToken}`;
    if (proxy) {
        config.httpsAgent = new HttpsProxyAgent(normalizeProxy(proxy));
    }
    try {
        const response = await axios(config);
        return response.data;
    } catch (error) {
        throw new Error(error.response?.data?.message || error.message);
    }
}

async function generateNonce(wallet) {
    const response = await apiRequest(
        `${API_BASE_URL}/wallet/generateNonce`,
        'POST',
        { walletAddress: wallet.address },
        null,
        wallet.proxy
    );
    if (response.code === 200) {
        if (response.result?.nonce) {
            return response.result.nonce;
        } else if (typeof response.result === 'string') {
            const nonceMatch = response.result.match(/Nonce: (.*)$/m);
            if (nonceMatch && nonceMatch[1]) {
                return nonceMatch[1];
            }
        }
    }
    throw new Error('Failed to generate nonce: ' + (response.message || 'Unknown error'));
}

async function login(wallet, nonce) {
    const message = `Taker quest needs to verify your identity to prevent unauthorized access. Please confirm your sign-in details below:\n\naddress: ${wallet.address}\n\nNonce: ${nonce}`;
    const ethersWallet = new ethers.Wallet(wallet.privateKey);
    const signature = await ethersWallet.signMessage(message);
    const response = await apiRequest(
        `${API_BASE_URL}/wallet/login`,
        'POST',
        { address: wallet.address, signature, message },
        null,
        wallet.proxy
    );
    if (response.code === 200) {
        return response.result.token;
    }
    throw new Error('Login failed: ' + response.message);
}

async function getUserInfo(wallet, token) {
    const response = await apiRequest(
        `${API_BASE_URL}/user/info`,
        'GET',
        null,
        token,
        wallet.proxy
    );
    if (response.code === 200) {
        return response.result;
    }
    throw new Error('Failed to fetch user info: ' + response.message);
}

async function performSignIn(wallet, token) {
    const response = await apiRequest(
        `${API_BASE_URL}/task/signIn?status=true`,
        'GET',
        null,
        token,
        wallet.proxy
    );
    if (response.code === 200) {
        logMessage('Sign-in successful!', 'success', wallet.address);
        return true;
    }
    logMessage('Sign-in failed: ' + response.message, 'error', wallet.address);
    return false;
}

function formatTimeRemaining(timestamp) {
    const now = Date.now();
    const timeLeft = timestamp - now;
    if (timeLeft <= 0) return '00:00:00';
    const hours = Math.floor(timeLeft / (1000 * 60 * 60));
    const minutes = Math.floor((timeLeft % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((timeLeft % (1000 * 60)) / 1000);
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
}

async function updateUserInfo(wallet, token) {
    try {
        if (!token) {
            console.log(`${colors.yellow('Wallet Address:')} ${colors.green(wallet.address)}`);
            console.log(colors.red('Not authenticated'));
            return;
        }
        const userInfo = await getUserInfo(wallet, token);
        console.log(`${colors.yellow('Wallet Address:')} ${colors.green(userInfo.walletAddress)}`);
        console.log(`${colors.yellow('Taker Points:')} ${colors.green(userInfo.takerPoints)}`);
        console.log(`${colors.yellow('Consecutive Sign-Ins:')} ${colors.green(userInfo.consecutiveSignInCount)}`);
        console.log(`${colors.yellow('Reward Count:')} ${colors.green(userInfo.rewardCount)}`);
    } catch (error) {
        logMessage('Error updating user info: ' + error.message, 'error', wallet.address);
    }
}

async function updateFarmingStatus(wallet, token) {
    try {
        const proxyDisplay = wallet.proxy ? normalizeProxy(wallet.proxy) : 'None';
        if (!token) {
            console.log(`${colors.yellow('Wallet Address:')} ${colors.green(wallet.address)}`);
            console.log(`${colors.yellow('Proxy:')} ${colors.green(proxyDisplay)}`);
            console.log(colors.red('Not authenticated'));
            return;
        }
        const userInfo = await getUserInfo(wallet, token);
        if (userInfo.nextTimestamp && userInfo.nextTimestamp > Date.now()) {
            console.log(`${colors.yellow('Wallet Address:')} ${colors.green(wallet.address)}`);
            console.log(`${colors.yellow('Proxy:')} ${colors.green(proxyDisplay)}`);
            console.log(`${colors.yellow('Farming Status:')} ${colors.green('ACTIVE')}`);
            console.log(`${colors.yellow('Next Farming Time:')} ${colors.green(new Date(userInfo.nextTimestamp).toLocaleString())}`);
            console.log(`${colors.yellow('Time Remaining:')} ${colors.green(formatTimeRemaining(userInfo.nextTimestamp))}`);
        } else {
            console.log(`${colors.yellow('Wallet Address:')} ${colors.green(wallet.address)}`);
            console.log(`${colors.yellow('Proxy:')} ${colors.green(proxyDisplay)}`);
            console.log(`${colors.yellow('Farming Status:')} ${colors.red('INACTIVE')}`);
            console.log(`${colors.yellow('Action:')} ${colors.yellow('Attempting to start farming...')}`);
            const signInSuccess = await performSignIn(wallet, token);
            if (signInSuccess) {
                const updatedUserInfo = await getUserInfo(wallet, token);
                console.log(`${colors.yellow('Farming Status:')} ${colors.green('ACTIVE')}`);
                console.log(`${colors.yellow('Next Farming Time:')} ${colors.green(new Date(updatedUserInfo.nextTimestamp).toLocaleString())}`);
                console.log(`${colors.yellow('Time Remaining:')} ${colors.green(formatTimeRemaining(updatedUserInfo.nextTimestamp))}`);
            }
        }
    } catch (error) {
        logMessage('Error updating farming status: ' + error.message, 'error', wallet.address);
    }
}

function startCountdown(wallet, token, nextTimestamp) {
    const updateCountdown = async () => {
        const now = Date.now();
        const timeLeft = nextTimestamp - now;
        if (timeLeft <= 0) {
            logMessage('Ready to farm again!', 'success', wallet.address);
            clearInterval(wallet.countdownInterval);
            if (currentWalletIndex === wallets.indexOf(wallet)) {
                await updateFarmingStatus(wallet, token);
            }
            return;
        }
        if (currentWalletIndex === wallets.indexOf(wallet)) {
            const proxyDisplay = wallet.proxy ? normalizeProxy(wallet.proxy) : 'None';
            console.log(`${colors.yellow('Wallet Address:')} ${colors.green(wallet.address)}`);
            console.log(`${colors.yellow('Proxy:')} ${colors.green(proxyDisplay)}`);
            console.log(`${colors.yellow('Farming Status:')} ${colors.green('ACTIVE')}`);
            console.log(`${colors.yellow('Next Farming Time:')} ${colors.green(new Date(nextTimestamp).toLocaleString())}`);
            console.log(`${colors.yellow('Time Remaining:')} ${colors.green(formatTimeRemaining(nextTimestamp))}`);
        }
    };
    updateCountdown();
    wallet.countdownInterval = setInterval(updateCountdown, 1000);
}

async function runBot() {
    logMessage(`Starting Taker Farming Bot for ${wallets.length} wallet(s)`, 'info');

    for (const wallet of wallets) {
        try {
            logMessage(`Using proxy: ${wallet.proxy || 'None'}`, 'info', wallet.address);
            const nonce = await generateNonce(wallet);
            logMessage('Nonce generated: ' + nonce, 'info', wallet.address);
            const token = await login(wallet, nonce);
            tokens[wallet.address] = token;
            logMessage('Login successful! Token received.', 'success', wallet.address);
        } catch (error) {
            logMessage('Login failed: ' + error.message, 'error', wallet.address);
        }
    }

    if (Object.keys(tokens).length === 0) {
        logMessage('No wallets authenticated. Exiting...', 'error');
        return;
    }

    const firstWallet = wallets[currentWalletIndex];
    await updateUserInfo(firstWallet, tokens[firstWallet.address]);
    await updateFarmingStatus(firstWallet, tokens[firstWallet.address]);

    for (const wallet of wallets) {
        const token = tokens[wallet.address];
        if (token) {
            const userInfo = await getUserInfo(wallet, token);
            if (userInfo.nextTimestamp && userInfo.nextTimestamp > Date.now()) {
                // startCountdown(wallet, token, userInfo.nextTimestamp);
            }
        }
    }

    setInterval(async () => {
        const wallet = wallets[currentWalletIndex];
        await updateUserInfo(wallet, tokens[wallet.address]);
        await updateFarmingStatus(wallet, tokens[wallet.address]);
    }, 30000);

}

runBot();

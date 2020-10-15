
/* Secrets! (not stored on the repository) */
const OAUTH_SECRETS = require('./client_secret.json').web;

/* Dependencies */
const {google} = require('googleapis');
const express = require('express');
const {DNS} = require('@google-cloud/dns');
const {Element, Document} = require('void-template');
const Firestore = require('@google-cloud/firestore');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const {v4: uuidv4} = require('uuid');
const { parse } = require('path');


/* Definitions */
const ECCS_HOSTED_DOMAIN = 'g.ecc.u-tokyo.ac.jp';
const ECCS_ID_PATTERN = /^([0-9]{10})@g\.ecc\.u-tokyo\.ac\.jp$/;

const DOMAIN = 'u-tokyo.app.';
const TYPE_WHITELIST = [
    'a', 'cname', 'aaaa', 'caa', 'txt', 'mx', 'ns', 'spf', 'srv', 'sshfp',
];
const DEFAULT_TTL = 300;

const AUTH_URL = 'https://www.u-tokyo.app/auth';

const oauth2Scopes = [
    'openid',
    'email',
    'profile',
];


/* Global objects */

const oauth2Client = new google.auth.OAuth2(
    OAUTH_SECRETS.client_id,
    OAUTH_SECRETS.client_secret,
    AUTH_URL
);

const app = express();

const db = new Firestore({
    projectId: 'utokyo',
});

const oauth2 = google.oauth2('v2');
const people = google.people('v1');

const dns = new DNS();

const zone = dns.zone('utokyo-app');


class User
{
    static async getUserByUtokyoId(id)
    {
        const usersRef = db.collection('users');
        const usersSnapshot = await usersRef.where('utokyo_id', '==', id).get();
        if (usersSnapshot.empty) {
            throw new Error('No such user');
        }
        const usersData = [];
        usersSnapshot.forEach(doc => usersData.push(doc.data()));
        return usersData[0];
    }

    static async initializeUserByUtokyoId(id)
    {
        try {
            return await User.getUserByUtokyoId(id);
        } catch (e) {
            const usersRef = db.collection('users');
            await usersRef.doc().set({
                utokyo_id: id,
                created_date: Firestore.FieldValue.serverTimestamp(),
                user_secret: crypto.randomBytes(32).toString('hex'),
            });
            return await User.getUserByUtokyoId(id);
        }
    }

    static async getUserTokenByUtokyoId(id)
    {
        const user = await User.initializeUserByUtokyoId(id);
        return jwt.sign({
            id: user.utokyo_id,
        }, user.user_secret, {
            expiresIn: 60 * 60 * 24, // one day
        });
    }

    static async verifyUserToken(id, token)
    {
        const user = await User.getUserByUtokyoId(id);
        return jwt.verify(token, user.user_secret);
    }
}

class Subdomain
{
    constructor(id)
    {
        this._docRef = db.collection('domains').doc(id);
    }

    async getAllSubdomains()
    {
        if (this._subdomains) {
            return this._subdomains;
        }

        const doc = await this._docRef.get();
        if (!doc.exists) {
            throw new Error('No such subdomain');
        }

        return this._subdomains = doc.data().subdomains;
    }

    async getBaseSubdomains()
    {
        const subdomains = await this.getAllSubdomains();
        return subdomains.filter(subdomain => !subdomain.includes('.'));
    }

    async assertSubdomain(aSubdomain)
    {
        const subdomain = (aSubdomain || '').toLowerCase();
        const baseSubdomain = subdomain.split('.').pop();
        const subdomains = await this.getAllSubdomains();
        if (!subdomains.includes(baseSubdomain)) {
            throw new Error('Subdomain mismatch');
        }

        return subdomain;
    }

    async addSubdomain(aSubdomain)
    {
        const subdomain = await this.assertSubdomain(aSubdomain);
        const subdomains = await this.getAllSubdomains();
        if (!subdomains.includes(subdomain)) {
            await this._docRef.update({
                subdomains: Firestore.FieldValue.arrayUnion(subdomain),
            });
            delete this._subdomains;
        }
    }

    async removeSubdomain(subdomain)
    {
        subdomain = (subdomain || '').toLowerCase();
        const baseSubdomain = subdomain.split('.').pop();
        if (subdomain != baseSubdomain) {
            await this._docRef.update({
                subdomains: Firestore.FieldValue.arrayRemove(subdomain),
            });
            delete this._subdomains;
        }
    }

    validateType(aType)
    {
        const type = ((aType || '') + '').toLowerCase();
        if (!TYPE_WHITELIST.includes(type)) {
            throw new Error('Invalid type');
        }
        return type;
    }

    createRecord(aType, aName, aValue)
    {
        const value = (aValue || '') + '';
        const type = this.validateType(aType);
        const name = ((aName || '') + '').toLowerCase();

        const quarifiedName = name + '.' + DOMAIN;
        const record = zone.record(type, {
            name: quarifiedName,
            data: value.split('\n')
                .map(value => value.trim())
                .filter(value => '' != value),
            ttl: DEFAULT_TTL,
        });
        return record;
    }

    async getRecords(subdomain)
    {
        const [records] = await zone.getRecords({
            name: subdomain + '.' + DOMAIN,
        });
        return records;
    }

    async getRecordsByType(aType, aName)
    {
        const type = this.validateType(aType);
        const [records] = await zone.getRecords({
            name: aName + '.' + DOMAIN,
            type: type.toUpperCase(),
        });
        return records;
    }

    async getRecordsByTypeFormatted(aType, aName)
    {
        const results = [];
        const records = await this.getRecordsByType(aType, aName);
        for (const {name, data, type} of records) {
            const suffix = '.' + DOMAIN;
            const plainName = name.endsWith(suffix) ? name.slice(0, -suffix.length) : name;
            const record = {
                name: plainName.toLowerCase(),
                data: data.join('\n'),
                type: type.toUpperCase(),
            };
            // console.log(record);
            results.push(record);
        }
        return results;
    }

    async getAllRecords()
    {
        const subdomains = await this.getAllSubdomains();
        const results = [];

        for (const subdomain of subdomains) {
            const records = await this.getRecords(subdomain);

            for (const {name, data, type} of records) {
                const suffix = '.' + DOMAIN;
                const plainName = name.endsWith(suffix) ? name.slice(0, -suffix.length) : name
                const record = {
                    name: plainName.toLowerCase(),
                    data: data.join('\n'),
                    type: type.toUpperCase(),
                };
                // console.log(record);
                results.push(record);
            }
        }

        return results;
    }

    async updateRecord(aType, aName, aNewValue)
    {
        await this.addSubdomain(aName);
        const oldRecords = await this.getRecordsByType(aType, aName);
        //const oldRecord = this.createRecord(aType, aName, aOldValue);
        const newRecord = this.createRecord(aType, aName, aNewValue);

        await zone.createChange({
            add: newRecord,
            delete: oldRecords,
        });
    }

    async deleteRecord(aType, aName)
    {
        const subdomain = await this.assertSubdomain(aName);
        const oldRecords = await this.getRecordsByType(aType, aName);
        await zone.deleteRecords(oldRecords);
        if (subdomain.split('.').length < 2) return;
        const leftRecords = await this.getRecords(subdomain);
        if (leftRecords.length < 1) {
            this.removeSubdomain(subdomain);
        }
    }

    static async domainExists(aName)
    {
        const domainsRef = db.collection('domains');
        const name = String(aName).toLowerCase();
        if (name.includes('.')) {
            throw new TypeError('Not a top-level subdomain');
        }
        const domainsSnapshot = await domainsRef.where('subdomains', 'array-contains', name).get();
        return !domainsSnapshot.empty;
    }

    static async createSubdomain(aName, aOwner)
    {
        const domainsRef = db.collection('domains');
        const name = String(aName).toLowerCase();

        if (!name.match(/^[a-z0-9]+(-[a-z0-9]+)*$/)) {
            throw new Error('Invalid name');
        }
        const exists = await Subdomain.domainExists(name);
        if (exists) {
            throw new Error('Domain already exists');
        }

        const id = uuidv4();
        await domainsRef.doc(id).set({
            created_by: aOwner,
            created_date: Firestore.FieldValue.serverTimestamp(),
            subdomains: [name],
        });

        return id;
    }
}

const parseCookies = header => {
    const cookies = Object.create(null);
    if (!header) {
        return cookies;
    }
    String(header).split('; ').forEach(rawCookie => {
        const [key, value] = rawCookie.split('=');
        cookies[key] = value;
    });
    return cookies;
};

app.get('/', (req, res) => {
    const cookies = parseCookies(req.headers.cookie);
    const user_id = cookies.utokyo_id || '';
    const user_token = cookies.utokyo_token || '';
    const document = new Document;
    document.documentElement.setAttribute('data-user_id', user_id);
    document.documentElement.setAttribute('data-user_token', user_token);
    
    document.title = 'Test document';

    res.send(document + '');
});


app.get('/login', async (req, res) => {
    const url = oauth2Client.generateAuthUrl({
        access_type: 'online',
        scope: oauth2Scopes,
    });
    res.redirect(url + '&hd=' + ECCS_HOSTED_DOMAIN);
});

app.get('/auth', async (req, res) => {
    try {
        const code = req.query.code;
        if (!code) throw new Error('No code provided');
        const {tokens} = await oauth2Client.getToken(code);
        oauth2Client.setCredentials(tokens);
        google.options({auth: oauth2Client});

        const person = (await people.people.get({
            resourceName: 'people/me',
            personFields: 'emailAddresses',
        })).data;

        const utokyoIds = [];
        for (const obj of person.emailAddresses) {
            if ('string' != typeof obj.value) continue;
            const matches = obj.value.match(ECCS_ID_PATTERN);
            if (matches) {
                utokyoIds.push(matches[1]);
            }
        }

        if (utokyoIds.length < 1) {
            throw new Error('No UTokyo account ID available for account');
        }

        const utokyo_id = utokyoIds[0];
        const token = await User.getUserTokenByUtokyoId(utokyo_id);

        res.cookie('utokyo_id', utokyo_id, {
            maxAge: 60 * 60 * 24,
            httpOnly: true,
            secure: true,
            sameSite: 'lax',
        });

        res.cookie('utokyo_token', token, {
            maxAge: 60 * 60 * 24,
            httpOnly: true,
            secure: true,
            sameSite: 'lax',
        });

        res.redirect('/');
    } catch (e) {
        console.error(e);
        res.status(400).contentType('application/json').send(JSON.stringify({
            error: e + '',
        }));
    }
});

app.post('/internal/create-domain', async (req, res) => {
    try {
        const cookies = Object.create(null);
        if (!req.query.user_id || !req.query.user_token) {
            throw new Error('No token provided');
        }

        await User.verifyUserToken(req.query.user_id, req.query.user_token);

        // verified
        if (!req.query.name) {
            throw new Error('Domain name not provided');
        }

        const id = await Subdomain.createSubdomain(req.query.name, req.query.user_id);
        res.status(200).contentType('application/json').send(JSON.stringify({
            id,
        }));
    } catch (e) {
        console.error(e);
        res.status(400).contentType('application/json').send(JSON.stringify({
            error: e + '',
        }));
    }
});

app.get('/api/v1/domain-info/:domain_id', async (req, res) => {
    try {
        const obj = new Subdomain(req.params.domain_id);
        const subdomains = await obj.getBaseSubdomains();
        res.status(200).contentType('application/json').send(JSON.stringify({
            subdomains,
        }));
    } catch (e) {
        console.error(e);
        res.status(400).contentType('application/json').send(JSON.stringify({
            error: e + '',
        }));
    }
});

app.get('/api/v1/list-records/:domain_id', async (req, res) => {
    try {
        const obj = new Subdomain(req.params.domain_id);
        const records = await obj.getAllRecords();
        res.status(200).contentType('application/json').send(JSON.stringify({
            records,
        }));
    } catch (e) {
        console.error(e);
        res.status(400).contentType('application/json').send(JSON.stringify({
            error: e + '',
        }));
    }
});

app.post('/api/v1/update-records/:domain_id/:name/:type', async (req, res) => {
    try {
        const obj = new Subdomain(req.params.domain_id);
        await obj.updateRecord(req.params.type, req.params.name, req.query.data);
        res.status(200).contentType('application/json').send(JSON.stringify({
            success: true,
        }));
    } catch (e) {
        console.error(e);
        res.status(400).contentType('application/json').send(JSON.stringify({
            error: e + '',
        }));
    }
});

app.post('/api/v1/delete-records/:domain_id/:name/:type', async (req, res) => {
    try {
        const obj = new Subdomain(req.params.domain_id);
        await obj.deleteRecord(req.params.type, req.params.name);
        res.status(200).contentType('application/json').send(JSON.stringify({
            success: true,
        }));
    } catch (e) {
        console.error(e);
        res.status(400).contentType('application/json').send(JSON.stringify({
            error: e + '',
        }));
    }
});

app.get('/api/v1/get-records/:domain_id/:name/:type', async (req, res) => {
    try {
        const obj = new Subdomain(req.params.domain_id);
        const records = await obj.getRecordsByTypeFormatted(req.params.type, req.params.name);
        res.status(200).contentType('application/json').send(JSON.stringify({
            records,
        }));
    } catch (e) {
        console.error(e);
        res.status(400).contentType('application/json').send(JSON.stringify({
            error: e + '',
        }));
    }
});

const PORT = process.env.PORT || 8080;
const server = app.listen(PORT, () => {
    const host = server.address().address;
    const port = server.address().port;

    // console.log(`UTokyo Students Domain app listening at http://${host}:${port}`);
});

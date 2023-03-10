const { SlashCommandBuilder, EmbedBuilder } = require('discord.js');
const fetch = require('node-fetch');
const { apiKey } = require('../config.json');
const { createHash } = require('crypto');

module.exports = {
	data: new SlashCommandBuilder()
		.setName('scan')
		.setDescription('Scan a URL')
        .addStringOption(option =>
            option.setName('url')
                .setDescription('URL to be scanned')
                .setRequired(true)),

	async execute(interaction) {

        await interaction.deferReply();

        const Scan = new ScanResult(interaction.options.get('url'));
        await Scan.getReport();

        await interaction.editReply( { embeds: [Scan.output] } );
        
	},
};

class ScanResult{
    constructor(url){
        this.url = url.value;
    }

    output = undefined;

    extractData(report){

        report = JSON.parse(report);

        let data = {

            analysisStats: report['data']['attributes']['last_analysis_stats'],
            reputation: report['data']['attributes']['reputation'],

            virusTotalLink: report['data']['links']['self'],
            timesScanned: report['data']['attributes']['times_submitted']
        };

        if(report['data']['attributes']['html_meta']){

            let description;
            const htmlMeta = report['data']['attributes']['html_meta'];

            if(htmlMeta['description']) description = htmlMeta['description'];
            else description = htmlMeta['Description'];

            Object.assign(data, {
                url: report['data']['attributes']['url'],
                title: report['data']['attributes']['title'],
                description: description
            });
        }
        
        return data;

    }

    formatReport(data){

        const AS = data.analysisStats;
        const totalVendors = AS['harmless'] + AS['malicious'] + AS['suspicious'] + AS['undetected'] + AS['timeout'];

        function determineSafety(){

            let sortedCategories = [];
            for (var catergory in AS) {
                sortedCategories.push([catergory, AS[catergory]]);
            }

            sortedCategories.sort(function(a, b) {
                return b[1] - a[1];
            });

            const Category = sortedCategories[0][0].charAt(0).toUpperCase() + sortedCategories[0][0].slice(1);

            const NumberMaliciousOrSuspicious = AS['malicious'] + AS['suspicious'];

            return [Category, NumberMaliciousOrSuspicious];

        }

        function reputationBand(score){

            if (score == 0) return '';
            else if (score < 100 && score > 0) return '(GOOD)';
            else if (score >= 100) return '(VERY GOOD)';
            else if (score > -100 && score < 0) return '(BAD)';
            else if (score <= -100) return '(VERY BAD)';

        }

        const safetyInfo = determineSafety();

        const embed = new EmbedBuilder()
            .setColor(0x0099FF)
            .setTitle(`Scan Result for \`${this.url}\``)
            .addFields(

                { name: 'Analysis Stats', value: `\`\`\`${safetyInfo[0]}\`\`\`**${safetyInfo[1]} out of ${totalVendors}** vendors reported the URL as malicious or suspicious.` },

                { name: 'Reputation', value: `\`\`\`${data.reputation} ${reputationBand(data.reputation)}\`\`\`` },

            )
            .setFooter({ text: `URL has been scanned ${data.timesScanned} times` })
            .setAuthor({ name: 'Click here to view full report', url: data.virusTotalLink });

        if(data.description){
            embed.addFields(
                { name: 'Title', value: data.title, inline: true },
                { name: 'Description', value: data.description[0], inline: true },
                { name: 'Final URL', value: data.url, inline: true }
            );
        }

        this.output = embed;

    }

    async getReport(){

        function scanURL(urlToScan){
            const form = new URLSearchParams({ url: urlToScan });
    
            const requestOptions = {
                method: 'POST',
                body: form,
                headers: {
                    'x-apikey': apiKey,
            }}
    
            return fetch(`https://www.virustotal.com/api/v3/urls`, requestOptions);
            
        }

        async function getURL(urlToGet){
            let urlId = Buffer.from(urlToGet).toString('base64');
            urlId = urlId.replaceAll('=', '').trim();
    
            const requestOptions = {
                method: 'GET',
                headers: {
                    'x-apikey': apiKey
            }}
    
            const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, requestOptions)
            const text = await response.text();

            return text;
        }
        
        await scanURL(this.url);

        const data = await new Promise(resolve => {
            setTimeout(async () => {

                setTimeout(async () => {
                    const urlData = await getURL(this.url);
                    resolve(urlData);
                }, 12000)

            }, 3000); // wait for 2.5 seconds to give time for the scan to complete
        });

        if(data['data']){
            this.formatReport(this.extractData(data));
        }
        else{
            this.output = new EmbedBuilder()
                .setColor(0x0099FF)
                .setTitle(`Error scanning \`${this.url}\``)
                .setDescription(
                    'There was an error. This could either be because you entered the URL in wrong or because the bot/API is incomplete.'
                );
        }
    

    }

}
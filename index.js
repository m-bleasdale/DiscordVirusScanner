const fs = require('node:fs');
const path = require('node:path');
const { Client, Events, Collection, GatewayIntentBits } = require('discord.js');
const { token } = require('./config.json');
const deployCommands = require('./deploy-commands');

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

client.commands = new Collection();

const commandsPath = path.join(__dirname, 'commands');
const commandFiles = fs.readdirSync(commandsPath).filter(file => file.endsWith('.js'));

commandFiles.forEach(file => {
    const filePath = path.join(commandsPath, file);
	const command = require(filePath);

    client.commands.set(command.data.name, command);

});

client.once(Events.ClientReady, () => {
	console.log('bot ready');
});

client.on("guildCreate", guild => {
    deployCommands.deployCommands(guild.id);
})

client.on(Events.InteractionCreate, async interaction => {
	if (!interaction.isChatInputCommand()) return;

	const command = interaction.client.commands.get(interaction.commandName);

	if (!command) {
		console.error(`\`${interaction.commandName}\` is not a command!`);
		return;
	}

	await command.execute(interaction);
});

client.login(token);

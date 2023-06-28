<script lang="ts">
	import { AppConfig, showConnect, UserSession, openSignatureRequestPopup } from '@stacks/connect';
	const appDetails = {
		name: 'Hiro + SvelteKit',
		icon: 'https://placekitten.com/200/200'
	};
	const appConfig = new AppConfig(['store_write', 'publish_data']);
	const userSession = new UserSession({ appConfig });

	const signMessage = async (
		message: string
	): Promise<{ signature: string; publicKey: string }> => {
		let _signature = '';
		let _publicKey = '';
		await openSignatureRequestPopup({
			message,
			appDetails,
			userSession,
			onFinish: async ({ signature, publicKey }) => {
				// console.log('Signature of the message', signature);
				// console.log('Use public key:', publicKey);
				console.log(JSON.stringify({ publicKey, signature, message }));
				_signature = signature;
				_publicKey = publicKey;
			}
		});
		return { signature: _signature, publicKey: _publicKey };
	};

	const connect = () => {
		try {
			return showConnect({
				appDetails,
				redirectTo: '/',

				onFinish: () => {
					const userData = userSession.loadUserData();
					if (userData) {
						console.log(userData);
					}
				},
				userSession
			});
		} catch (error) {
			console.log(error);
		}
	};

	$: console.log(userSession.isUserSignedIn());
</script>

{#if userSession.isUserSignedIn()}
	<button on:click={() => signMessage('hello')} class="btn"> Sign Message </button>
{:else}
	<button on:click={connect} class="btn"> Connect Hiro Wallet </button>
{/if}

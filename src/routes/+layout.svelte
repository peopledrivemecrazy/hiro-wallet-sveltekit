<script lang="ts">
	import { base } from '$app/paths';
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

	const signBip = async (message: string) => {
		const response = await window.btc.request('signMessage', {
			message,
			paymentType: 'p2tr' // or 'p2wphk' (default)
		});
		const r = await fetch(`${base}/api`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify(response)
		});
		console.log(response);
	};
	$: signedIn = userSession.isUserSignedIn();

	const connect = () => {
		try {
			return showConnect({
				appDetails,
				redirectTo: '/',

				onFinish: () => {
					const userData = userSession.loadUserData();
					if (userData) {
						console.log(userData);
						if (userData.profile) signedIn = true;
					}
				},
				userSession
			});
		} catch (error) {
			console.log(error);
		}
	};

	$: console.log(signedIn);
</script>

{#if signedIn}
	<button on:click={() => signMessage('hello')} class="btn"> Sign Message </button>
	<button on:click={() => signBip('Hello World')} class="btn"> Sign BIP322 Message </button>
	<slot />
{:else}
	<button on:click={connect} class="btn"> Connect Hiro Wallet </button>
{/if}

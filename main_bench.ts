/** @format */

import * as totp from "./main.ts";

Deno.bench(function generateTotp() {
	totp.generateTOTP();
});

Deno.bench(function workflow() {
	const generated = totp.generateTOTP();
	totp.getTOTPAuthUri({
		...generated,
		issuer: "Deno",
		accountName: "Deno Benchmark",
	});
});

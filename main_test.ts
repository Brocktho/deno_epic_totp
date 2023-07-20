/** @format */

import * as totp from "./main.ts";
import { faker } from "@faker-js/faker";
import { encode } from "https://deno.land/std@0.194.0/encoding/base64.ts";
import {
	assertEquals,
	assertExists,
	assertMatch,
	assertNotEquals,
} from "https://deno.land/std@0.194.0/testing/asserts.ts";
import { FakeTime } from "https://deno.land/std@0.194.0/testing/time.ts";

Deno.test("OTP can be generated and verified", () => {
	const { secret, otp, algorithm, period } = totp.generateTOTP();
	const result = totp.verifyTOTP({ otp, secret });
	assertEquals(result, { delta: 0 });
	assertEquals(algorithm, "SHA256");
	assertEquals(period, 30);
});

Deno.test("Verify TOTP within the specified time window", () => {
	const time = new FakeTime();
	try {
		const { otp, secret } = totp.generateTOTP();
		const result = totp.verifyTOTP({ otp, secret });
		assertNotEquals(result, null);
	} finally {
		time.restore();
	}
});

Deno.test("Fail to verify an invalid TOTP", () => {
	const secret = encode(faker.string.alphanumeric());
	const tooShortNumber = faker.string.numeric({ length: 5 });
	const result = totp.verifyTOTP({ otp: tooShortNumber, secret });
	assertEquals(result, null);
});

Deno.test("Fail to verify TOTP outside the specified time window", () => {
	const time = new FakeTime();
	try {
		const { otp, secret: key } = totp.generateTOTP();
		const futureDate = Date.now() + 1000 * 60 * 60 * 24;
		time.tick(futureDate);
		const result = totp.verifyTOTP({ otp, secret: key });
		assertEquals(result, null);
	} finally {
		time.restore();
	}
});

Deno.test("Clock drift is handled by window", () => {
	const time = new FakeTime();
	try {
		const { otp, secret: key } = totp.generateTOTP({ period: 60 });
		const futureDate = 61 * 1000;
		time.tick(futureDate);
		const result = totp.verifyTOTP({
			otp,
			secret: key,
			window: 2,
			period: 60,
		});
		assertEquals(result, { delta: -1 });
	} finally {
		time.restore();
	}
});

Deno.test(
	"Setting a different seconds config for generating and verifying will fail",
	() => {
		const desiredperiod = 60;
		const { otp, secret, period } = totp.generateTOTP({
			period: desiredperiod,
		});
		assertEquals(period, desiredperiod);
		const result = totp.verifyTOTP({ otp, secret, period: period + 1 });
		assertEquals(result, null);
	}
);

Deno.test(
	"Setting a different algo config for generating and verifying will fail",
	() => {
		const desiredAlgo = "SHA512";
		const { otp, secret, algorithm } = totp.generateTOTP({
			algorithm: desiredAlgo,
		});
		assertEquals(algorithm, desiredAlgo);
		const result = totp.verifyTOTP({ otp, secret, algorithm: "SHA1" });
		assertEquals(result, null);
	}
);

Deno.test(
	"Generating and verifying also works with the algorithm name alias",
	() => {
		const desiredAlgo = "SHA1";
		const { otp, secret, algorithm } = totp.generateTOTP({
			algorithm: desiredAlgo,
		});
		assertEquals(algorithm, desiredAlgo);

		const result = totp.verifyTOTP({ otp, secret, algorithm: "sha1" });
		assertExists(result);
	}
);

Deno.test("OTP Auth URI can be generated", () => {
	const { otp: _otp, secret, ...totpConfig } = totp.generateTOTP();
	const issuer = faker.company.name();
	const accountName = faker.internet.userName();
	const uri = totp.getTOTPAuthUri({
		issuer,
		accountName,
		secret,
		...totpConfig,
	});
	assertMatch(uri, /^otpauth:\/\/totp\/(.*)\?/);
});

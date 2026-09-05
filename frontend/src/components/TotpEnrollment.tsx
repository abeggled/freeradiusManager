import { QRCodeSVG } from "qrcode.react";

import { Copyable } from "@/components/ui";
import { useI18n } from "@/i18n";

/**
 * Einrichtung des zweiten Faktors: QR-Code zum Scannen, Geheimnis zum Abtippen.
 *
 * Der QR-Code traegt dieselbe ``otpauth``-Adresse, die auch als Text
 * bereitsteht - Authenticator-Apps lesen sie damit ohne Uebertragungsfehler.
 * Beides gehoert nebeneinander: nicht jede App kann scannen, und auf dem Geraet,
 * das den Code anzeigt, laesst sich nichts abfotografieren.
 */
export function TotpEnrollment({
  secret,
  provisioningUri,
}: {
  secret: string;
  provisioningUri: string;
}) {
  const { t } = useI18n();
  return (
    <div className="totp-setup">
      <p className="hint">{t("login.totpScan")}</p>
      {/* Heller Grund unabhaengig vom Farbschema: ein QR-Code auf dunklem
          Untergrund wird von vielen Kameras nicht erkannt. */}
      <div className="qr">
        <QRCodeSVG value={provisioningUri} size={176} level="M" marginSize={2} />
      </div>
      <p className="hint">{t("login.totpManual")}</p>
      <p>
        <strong>{t("login.totpSecret")}:</strong> <Copyable value={secret} />
      </p>
    </div>
  );
}

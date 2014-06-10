package edu.tamu.tcat.crypto.bouncycastle;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

public class InteropTest extends AsymmetricKeyTest
{
   private static class KeySet {
      public final String publicKey;
      public final String privateKey;
      public final String signature;
      public KeySet(String publicKey, String privateKey, String signature)
      {
         this.publicKey = publicKey;
         this.privateKey = privateKey;
         this.signature = signature;
      }
   }
   
   private static final KeySet spougyCastle = new KeySet(
         "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQApO8YOFXrgj+Yw9h8Ns56q3OFEyr4" +
         "5l96Wm2iU2fiqXSiCwL9ayo1/vX4cDlRqkRyTq6YLCPPi7n7hZFaMwfN9mcBxlXc" +
         "2kubiQSKCE+68+me01fgn2o9jxg9p84MJJnOR3jGoLoIUAdE2l8dq3JFSOGYQCCi" +
         "AWDpl6iwb8lL6QsQ9D8=",
         "MIIChQIBAQRBSiAOyV42+cAa3uHy2R5u61GvXkMFdMeb7BNTGfF+u6L7fO79LP9s" +
         "nHJN/K/W4qA2bXSDR8ENki8RRva19hyuqp6gggGvMIIBqwIBATBNBgcqhkjOPQEB" +
         "AkIB////////////////////////////////////////////////////////////" +
         "//////////////////////////8wgYcEQgH/////////////////////////////" +
         "/////////////////////////////////////////////////////////ARBUZU+" +
         "uWGOHJofkpohoLaFQO6i2nJbmbMV87i0iZGO8QnhVhk5Uex+k3sWUsC9O7G/BzVz" +
         "34g9LDTx70Uf1GtQPwAEgYUEAMaFjga3BATpzZ4+y2YjlbRCnGSBOQU/tSH4KK9g" +
         "a009uqFLXnfv51ko/h3BJ6L/qN4zSLPBhWpCm/l+fjHC5b1mARg5KWp4mjvABFyK" +
         "X7QsfRvZmPVESVebRGgXr70XJz5mLJfucple9CZAxVC5AT+tB2E1PHCGonLCQIi+" +
         "lHaf0WZQAkIB///////////////////////////////////////////6UYaHg78v" +
         "lmt/zAFI9wml0Du1ybiJnEeuu2+3HpE4ZAkCAQGhgYkDgYYABACk7xg4VeuCP5jD" +
         "2Hw2znqrc4UTKvjmX3pabaJTZ+KpdKILAv1rKjX+9fhwOVGqRHJOrpgsI8+LufuF" +
         "kVozB832ZwHGVdzaS5uJBIoIT7rz6Z7TV+Cfaj2PGD2nzgwkmc5HeMagughQB0Ta" +
         "Xx2rckVI4ZhAIKIBYOmXqLBvyUvpCxD0Pw==",
         "MIGIAkIBJChsFWymUGY3D8a475UlgZH4NKAqrvYg1MQKGC0GbjVGDjgNQMN1ypQj" +
         "jxT1obW8Yu7kk/tSmw1oPzpmfyO58x0CQgGZfK7JHhslL+iQJo0oMGWtVIEkh+ph" +
         "WqVHga2enZ8j5Uq+y74t+Et1LMJRSeaiRsgwXpCLsWmiYbMcMdAY5/uj8Q==");
   
   private static final KeySet openSSl = new KeySet(
         "MIICXDCCAc8GByqGSM49AgEwggHCAgEBME0GByqGSM49AQECQgH/////////////" +
         "////////////////////////////////////////////////////////////////" +
         "/////////zCBngRCAf//////////////////////////////////////////////" +
         "///////////////////////////////////////8BEFRlT65YY4cmh+SmiGgtoVA" +
         "7qLacluZsxXzuLSJkY7xCeFWGTlR7H6TexZSwL07sb8HNXPfiD0sNPHvRR/Ua1A/" +
         "AAMVANCeiAApHLhTlsxnFzkyhKqg2mS6BIGFBADGhY4GtwQE6c2ePstmI5W0Qpxk" +
         "gTkFP7Uh+CivYGtNPbqhS1537+dZKP4dwSei/6jeM0izwYVqQpv5fn4xwuW9ZgEY" +
         "OSlqeJo7wARcil+0LH0b2Zj1RElXm0RoF6+9Fyc+ZiyX7nKZXvQmQMVQuQE/rQdh" +
         "NTxwhqJywkCIvpR2n9FmUAJCAf//////////////////////////////////////" +
         "////+lGGh4O/L5Zrf8wBSPcJpdA7tcm4iZxHrrtvtx6ROGQJAgEBA4GGAAQBJJCV" +
         "wou2jVvznc52TQY2WWGworzI/yy0xRUkDdUPOJnC98FZ1+ti1fiiF3f5B8307iEb" +
         "iDcIT9Rt81cLesjWG/IAZGItYtRFmKoCg0Ml9urEdBN1mW5OhqUSxJAkcPXnm1bC" +
         "sZSazgWwcl1QMfZWWSNFw8/FfbUgV82Ez/ozGlpdkhM=",
         "MIICnAIBAQRBSOca0r30N55DifjFZd7PK6W1G4ZDyRVhoyo9gkiZjGUWdPb3i4NF" +
         "UxWITFoc9CcqXWZySDKxs9ayWdOEIytWGKGgggHGMIIBwgIBATBNBgcqhkjOPQEB" +
         "AkIB////////////////////////////////////////////////////////////" +
         "//////////////////////////8wgZ4EQgH/////////////////////////////" +
         "/////////////////////////////////////////////////////////ARBUZU+" +
         "uWGOHJofkpohoLaFQO6i2nJbmbMV87i0iZGO8QnhVhk5Uex+k3sWUsC9O7G/BzVz" +
         "34g9LDTx70Uf1GtQPwADFQDQnogAKRy4U5bMZxc5MoSqoNpkugSBhQQAxoWOBrcE" +
         "BOnNnj7LZiOVtEKcZIE5BT+1Ifgor2BrTT26oUted+/nWSj+HcEnov+o3jNIs8GF" +
         "akKb+X5+McLlvWYBGDkpaniaO8AEXIpftCx9G9mY9URJV5tEaBevvRcnPmYsl+5y" +
         "mV70JkDFULkBP60HYTU8cIaicsJAiL6Udp/RZlACQgH/////////////////////" +
         "//////////////////////pRhoeDvy+Wa3/MAUj3CaXQO7XJuImcR667b7cekThk" +
         "CQIBAaGBiQOBhgAEASSQlcKLto1b853Odk0GNllhsKK8yP8stMUVJA3VDziZwvfB" +
         "WdfrYtX4ohd3+QfN9O4hG4g3CE/UbfNXC3rI1hvyAGRiLWLURZiqAoNDJfbqxHQT" +
         "dZluToalEsSQJHD155tWwrGUms4FsHJdUDH2VlkjRcPPxX21IFfNhM/6MxpaXZIT",
         "MIGIAkIBm2yr+m9Mo9qAf4Zz7r5MMmXeg5Lp/BIQVkrmIFYuS35ST8hhcrPuwSCW" +
         "cmDiMGg1Ct9FEYomxokncGhQjYef4hYCQgC5pXhe73+Sk4D+d0d/xkdpI0jCA7rL" +
         "zWWHKHzZHMwy4y0AclYed7sg7JPikoA5zBdUrPTsfrafRvyF3IxHjDU5PAAA");
   
   private static final KeySet[] sets = {
      spougyCastle,
      openSSl,
   };
   
   @Test
   public void interoptTest() throws Exception
   {
      for (KeySet keySet : sets)
      {
         PublicKey publicKey = provider.getX509KeyDecoder().decodePublicKey("EC", Base64.decode(keySet.publicKey));
         PrivateKey privateKey = provider.getAsn1SeqKey().decodePrivateKey("EC", Base64.decode(keySet.privateKey));
         testVerify(publicKey, Base64.decode(keySet.signature));
         testSign(privateKey, publicKey);
      }
   }
}

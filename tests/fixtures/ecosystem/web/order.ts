const endpoint = "https://api.example.org/v2/orders?token=do-not-export";
export async function signOrder(wallet: any, order: any) {
  order.status = "pending";
  return wallet.signTypedData({ chainId: 1 }, order);
}
// Later processing may set filled; fixture text is not an execution proof.

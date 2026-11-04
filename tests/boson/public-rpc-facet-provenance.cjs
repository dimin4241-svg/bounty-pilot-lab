const {JsonRpcProvider,Contract,keccak256}=require('ethers');
const diamond='0x59A4C19b55193D5a2EAD0065c54af4d516E18Cb5';
const expected='0x34dcf2e8cb43a8f6d4c31fff6e0e9fbcbbb4e4f4b2c56ed40d39b3c3c181cac3';
const selector='0xed2fae6a';
const nets=[['1','Ethereum','https://ethereum-rpc.publicnode.com'],['10','Optimism','https://optimism-rpc.publicnode.com'],['137','Polygon','https://polygon-bor-rpc.publicnode.com'],['8453','Base','https://base-rpc.publicnode.com'],['42161','Arbitrum','https://arbitrum-one-rpc.publicnode.com']];
(async()=>{
const results=[];
for(const [chain,name,url] of nets){
  let row={chain,name};try{
    const p=new JsonRpcProvider(url,Number(chain),{staticNetwork:true,batchMaxCount:1});
    const d=new Contract(diamond,['function facetAddress(bytes4) view returns(address)','function getVersion() view returns(string)'],p);
    row.block=await p.getBlockNumber();
    row.version=(await d.getVersion()).replace(/\\u0000/g,'').replace(/\u0000/g,'').replace(/\x00/g,'');
    row.facet=await d.facetAddress(selector);
    const bytecode=await p.getCode(row.facet);
    row.bytecodeSize=(bytecode.length-2)/2;
    row.codehash=keccak256(bytecode);
    const metadataLength=parseInt(bytecode.slice(-4),16)+2;
    row.metadataBytes=metadataLength;
    row.executableHash=keccak256('0x'+bytecode.slice(2,-metadataLength*2));
    row.executableMatchesPinnedSource=row.executableHash==='0xde5650b145ffc25a01e838cd20ce0eb3d7a71d690221efd312d163dbe4b64d76';
    row.matchesPinnedSource=row.codehash===expected;
  }catch(e){row.error=String(e.shortMessage||e.message).slice(0,240)}
  console.log('BOSON_FACET_PROVENANCE '+JSON.stringify(row));
  results.push(row);
}
require('fs').writeFileSync(process.env.BOSON_PROVENANCE_FILE,JSON.stringify({expectedCompiledHash:expected,selector,diamond,results},null,2));
})();
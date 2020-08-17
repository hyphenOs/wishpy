jQuery(document).ready(() => {
  console.log("document.ready called.");
  document.querySelectorAll("a.reference.external").forEach( (link) => { link.target = "_blank" } );
});

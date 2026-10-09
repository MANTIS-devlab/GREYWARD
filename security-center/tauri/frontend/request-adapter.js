// Presentation wait limits do not cancel backend operations or authorize work.
(() => {
  function create({invoke, setTimer, clearTimer, timeoutMessage, observe = () => {}}) {
    return (command, args, timeoutMs = 10000) => {
      if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000) {
        return Promise.reject(new RangeError("Invalid presentation request deadline"));
      }
      observe(command);
      return new Promise((resolve, reject) => {
        let settled = false;
        const finish = (callback, result) => {
          if (settled) return;
          settled = true;
          clearTimer(timer);
          callback(result);
        };
        const timer = setTimer(() => {
          const error = new Error(timeoutMessage());
          error.code = "PRESENTATION_WAIT_TIMEOUT";
          error.backendCancelled = false;
          finish(reject, error);
        }, timeoutMs);
        // The deferred call also catches synchronous transport exceptions.
        Promise.resolve().then(() => invoke(command, args)).then(
          (result) => finish(resolve, result),
          (error) => finish(reject, error),
        );
      });
    };
  }
  window.GREYWARD_REQUESTS = Object.freeze({create});
})();

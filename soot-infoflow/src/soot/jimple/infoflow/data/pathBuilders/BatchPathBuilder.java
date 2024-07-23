package soot.jimple.infoflow.data.pathBuilders;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import soot.jimple.infoflow.AbstractInfoflow;
import soot.jimple.infoflow.InfoflowManager;
import soot.jimple.infoflow.data.AbstractionAtSink;
import soot.jimple.infoflow.memory.ISolverTerminationReason;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.solver.executors.InterruptableExecutor;

/**
 * Path builder that forwards all its requests to another path builder in
 * batches. This builder waits for each batch to complete before submitting
 * another batch. Use this path builder to reduce the memory consumption of the
 * path building process by keeping less paths in memory at the same time.
 *
 * @author Steven Arzt
 *
 */
public class BatchPathBuilder extends AbstractAbstractionPathBuilder {

    protected final IAbstractionPathBuilder innerBuilder;
    protected int batchSize = 5;
    protected ISolverTerminationReason terminationReason = null;

    public BatchPathBuilder(InfoflowManager manager, IAbstractionPathBuilder innerBuilder) {
        super(manager);
        this.innerBuilder = innerBuilder;
    }

    @Override
    public void computeTaintPaths(Set<AbstractionAtSink> res) {
        Set<AbstractionAtSink> batch = new HashSet<>();
        Iterator<AbstractionAtSink> resIt = res.iterator();
        int batchId = 1;

        //TODO(line 41~53) add a new control: Total time for computeTaintPaths(startTime\if)
        long startTime = System.nanoTime(); // 记录开始时间
        long totalTime=manager.getConfig().getPathConfiguration().getPathReconstructionTotalTime();
        while (resIt.hasNext()) {
            long executionNanoTime = System.nanoTime() - startTime;
            if (executionNanoTime / 1E9 >= totalTime) {
                logger.info("Path Reconstruction has terminated because it exceeds the AbstractInfoflow.pathReconstructionTotalTime.");
                logger.info("The AbstractInfoflow.pathReconstructionTotalTime is set to " + totalTime + "seconds");
                logger.info("Now batchId:" + batchId + "; And remain res:" + (res.size() - batchId * batch.size()));
                break;
            } else {
                logger.info("Path Reconstruction has used " + executionNanoTime / 1E9 + " seconds");
            }
            // Build the next batch
            while (batch.size() < this.batchSize && resIt.hasNext())
                batch.add(resIt.next());
            logger.info("Running path reconstruction batch {} with {} elements", batchId++, batch.size());

            // Run the next batch
            innerBuilder.reset();
            innerBuilder.computeTaintPaths(batch);

            // Save the termination reason
            if (this.terminationReason == null)
                this.terminationReason = innerBuilder.getTerminationReason();
            else
                this.terminationReason = this.terminationReason.combine(innerBuilder.getTerminationReason());

            // Wait for the batch to complete
            if (innerBuilder instanceof ConcurrentAbstractionPathBuilder) {
                ConcurrentAbstractionPathBuilder concurrentBuilder = (ConcurrentAbstractionPathBuilder) innerBuilder;
                final InterruptableExecutor resultExecutor = concurrentBuilder.getExecutor();
                try {
                    // The path reconstruction should stop on time anyway. In case it doesn't, we
                    // make sure that we don't get stuck.
                    long pathTimeout = manager.getConfig().getPathConfiguration().getPathReconstructionTimeout();
                    if (pathTimeout > 0)
                        resultExecutor.awaitCompletion(pathTimeout + 20, TimeUnit.SECONDS);
                    else
                        resultExecutor.awaitCompletion();
                } catch (InterruptedException e) {
                    logger.error("Could not wait for executor termination", e);
                }
                resultExecutor.reset();
            }

            // Prepare for the next batch
            batch.clear();
        }
    }

    @Override
    public InfoflowResults getResults() {
        return innerBuilder.getResults();
    }

    @Override
    public void runIncrementalPathComputation() {
        innerBuilder.runIncrementalPathComputation();
    }

    @Override
    public void forceTerminate(ISolverTerminationReason reason) {
        innerBuilder.forceTerminate(reason);
    }

    @Override
    public boolean isTerminated() {
        return innerBuilder.isTerminated();
    }

    @Override
    public boolean isKilled() {
        return innerBuilder.isKilled();
    }

    @Override
    public ISolverTerminationReason getTerminationReason() {
        return terminationReason;
    }

    @Override
    public void reset() {
        innerBuilder.reset();
    }

    @Override
    public void addStatusListener(IMemoryBoundedSolverStatusNotification listener) {
        innerBuilder.addStatusListener(listener);
    }

    /**
     * Sets the number of paths that shall be part of one batch, i.e., that shall be
     * forwarded to the inner path builder at the same time
     *
     * @param batchSize The number of paths in one batch
     */
    public void setBatchSize(int batchSize) {
        this.batchSize = batchSize;
    }

}

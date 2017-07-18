-- priority queue (min-heap) that stores all scheduled tasks.
-- insert: O(log n)
-- deleteMin: O(log n)
-- getMin: O(1)
-- removeAllMatching: O(n)

local insert, removeAllMatching, getMin, deleteMin
do
    local heap = {}
    local firstFree = 1

    -- gets the next task
    function getMin()
        return heap[1]
    end

    -- restores the heap invariant by moving an item up
    local function siftUp(n)
        local parent = floor(n / 2)
        while n > 1 and heap[parent].time > heap[n].time do -- move the element up until the heap invariant is restored, meaning the element is at the top or the element's parent is <= the element
            heap[n], heap[parent] = heap[parent], heap[n] -- swap the element with its parent
            n = parent
            parent = floor(n / 2)
        end
    end

    -- restores the heap invariant by moving an item down
    local function siftDown(n)
        local m -- position of the smaller child
        while 2 * n < firstFree do -- #children >= 1
            -- swap the element with its smaller child
            if 2 * n + 1 == firstFree then -- n does not have a right child --> it only has a left child as #children >= 1
                m = 2 * n -- left child
            elseif heap[2 * n].time < heap[2 * n + 1].time then -- #children = 2 and left child < right child
                m = 2 * n -- left child
            else -- #children = 2 and right child is smaller than the left one
                m = 2 * n + 1 -- right
            end
            if heap[n].time <= heap[m].time then -- n is <= its smallest child --> heap invariant restored
                return
            end
            heap[n], heap[m] = heap[m], heap[n]
            n = m
        end
    end

    -- inserts a new element into the heap
    function insert(ele)
        heap[firstFree] = ele
        siftUp(firstFree)
        firstFree = firstFree + 1
    end

    -- deletes the min element
    function deleteMin()
        local min = heap[1]
        firstFree = firstFree - 1
        heap[1] = heap[firstFree]
        heap[firstFree] = nil
        siftDown(1)
        return min
    end

    -- removes multiple scheduled tasks from the heap
    -- note that this function is comparatively slow by design as it has to check all tasks and allows partial matches
    function removeAllMatching(f, mod, ...)
        -- remove all elements that match the signature, this destroyes the heap and leaves a normal array
        local v, match
        local foundMatch = false
        for i = #heap, 1, -1 do -- iterate backwards over the array to allow usage of table.remove
            v = heap[i]
            if (not f or v.func == f) and (not mod or v.mod == mod) then
                match = true
                for i = 1, select("#", ...) do
                    if select(i, ...) ~= v[i] then
                        match = false
                        break
                    end
                end
                if match then
                    tremove(heap, i)
                    firstFree = firstFree - 1
                    foundMatch = true
                end
            end
        end
        -- rebuild the heap from the array in O(n)
        if foundMatch then
            for i = floor((firstFree - 1) / 2), 1, -1 do
                siftDown(i)
            end
        end
    end
end

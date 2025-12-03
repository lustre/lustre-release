# `rustreapi`

## Creating Files

### `OpenOptions`

```mermaid
classDiagram
    class OpenOptions {
        -bool read
        -bool write
        -bool append
        -bool truncate
        -bool create
        -bool create_new
        -mode_t mode
        -Option~Layout~ layout
        -i32 stripe_size
        -i32 stripe_offset
        -i32 stripe_count
        -i32 stripe_pattern
        -Option~String~ pool
        -bool lov_delay
        -Option~i32~ mdt
        +new() OpenOptions
        +read(bool) OpenOptions
        +write(bool) OpenOptions
        +create(bool) OpenOptions
        +open(Path) Result~File~
        +volatile(Path) Result~File~
    }

    class Fid {
        +to_lu_fid() lu_fid
    }

    class Layout {
        +as_lu_layout() *mut llapi_layout
    }

    OpenOptions --> Layout: uses
    OpenOptions --> File: creates
```

## Opening a File

A sequence diagram of the file open process:

```mermaid
sequenceDiagram
    participant C as Client
    participant O as OpenOptions
    participant L as Layout/Param
    participant A as LustreAPI
    C ->> O: create OpenOptions
    C ->> O: configure options
    C ->> O: open(path)
    alt Has Layout
        O ->> L: Get layout
        O ->> A: llapi_layout_file_open()
    else No Layout
        O ->> L: Create stripe parameter
        O ->> A: llapi_file_open_param()
    end
    A ->> O: Return file descriptor
    O ->> C: Return File
```

## HSM Copytool

This API divides the `lustreapi` copytool into two parts.

- Receive action lists from the Coordinator
- Process actions and send result to the Coordinator

### Receiving Actions

The `Copytool` object wraps a connection to the `HSM` coordinators in each of
the `MDTs.` If the non-blocking option is used when creating the `Copytool,`
then the `raw_fd` can be used to poll in asynchronous code. The `receive()`
method must still be used to fetch the actions, and it will return `EWOUDLBLOCK`
when there are no actions available.

```mermaid
sequenceDiagram
    participant Client
    participant CopytoolBuilder
    participant Copytool
    participant LustreCoordinator
    participant ActionList
    participant ActionItem
    Client ->> Copytool: builder()
    Copytool ->> CopytoolBuilder: default()
    Client ->> CopytoolBuilder: archives([archive_ids])
    Client ->> CopytoolBuilder: non_blocking(true/false)
    Client ->> CopytoolBuilder: register(mount_dir)
    CopytoolBuilder ->> LustreCoordinator: llapi_hsm_copytool_register()
    LustreCoordinator -->> CopytoolBuilder: hsm_copytool_private
    CopytoolBuilder -->> Client: Copytool
    Note over Client: For polling
    Client ->> Copytool: raw_fd()
    Copytool ->> LustreCoordinator: llapi_hsm_copytool_get_fd()
    Copytool -->> Client: RawDescriptor
    Note over Client: Wait for events (polling)
    Client ->> Copytool: receive()
    Copytool ->> LustreCoordinator: llapi_hsm_copytool_recv()
    LustreCoordinator -->> Copytool: hsm_action_list
    Copytool -->> Client: ActionList
    Client ->> ActionList: iter()
    ActionList -->> Client: ActionIterator
    loop For each action
        ActionList ->> ActionItem: next()
        ActionItem -->> Client: ActionItem
        Note over Client: Process action
    end
```

### Data Mover

```mermaid
sequenceDiagram
    participant Client
    participant MoverBuilder
    participant Mover
    participant ProgressBuilder
    participant ActionProgress
    participant LustreCoordinator
    Client ->> MoverBuilder: builder()
    Client ->> MoverBuilder: register(mount_dir)
    MoverBuilder ->> LustreCoordinator: llapi_hsm_mover_register()
    MoverBuilder -->> Client: Mover

    alt Process Action Successfully
        Client ->> ProgressBuilder: action_begin(mover, action_item, flags)
        ProgressBuilder ->> LustreCoordinator: llapi_hsm_action_begin()
        ProgressBuilder -->> Client: ActionProgress
        Client ->> ActionProgress: dfid()
        LustreCoordinator -->> Client: Fid
        Client ->> ActionProgress: data_file()
        LustreCoordinator -->> Client: File
        Note over Client: Process file data
        Client ->> ActionProgress: progress(extent, total, flags)
        ActionProgress ->> LustreCoordinator: llapi_hsm_action_progress()
        Client ->> ActionProgress: end(extent, HP_FLAG_COMPLETED, 0)
        ActionProgress ->> LustreCoordinator: llapi_hsm_action_end()
    else Report Error
        Client ->> ProgressBuilder: action_error(mover, action_item, retry, err_code)
        ProgressBuilder ->> LustreCoordinator: llapi_hsm_action_begin()
        LustreCoordinator -->> ProgressBuilder: ActionProgress
        ProgressBuilder ->> LustreCoordinator: llapi_hsm_action_end()
        ProgressBuilder -->> Client: Result<()>
    end

    Note over Mover: When done
    Client ->> Mover: drop()
    Mover ->> LustreCoordinator: llapi_hsm_mover_unregister()
```